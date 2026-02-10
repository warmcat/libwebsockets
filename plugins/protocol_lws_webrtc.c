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
 *
 * This is a shared WebRTC protocol plugin that handles signaling (WS),
 * DTLS, SRTP, and RTP packetization.
 */

#define LWS_DLL 1
#define _GNU_SOURCE
#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <libwebsockets/lws-rtp.h>
#include <libwebsockets/lws-srtp.h>
#include <libwebsockets/lws-stun.h>

#include "protocol_lws_webrtc.h"


static int
lws_webrtc_foreach_session(struct vhd_webrtc *vhd, lws_webrtc_session_iter_cb cb, void *user)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
		struct pss_webrtc *s = lws_container_of(d, struct pss_webrtc, list);
		if (cb(s, user))
			return 1;
	} lws_end_foreach_dll(d);

	return 0;
}

static void *
lws_webrtc_get_user_data(struct pss_webrtc *pss)
{
	return pss->user_data;
}

static void
lws_webrtc_set_user_data(struct pss_webrtc *pss, void *data)
{
	pss->user_data = data;
}

static int
lws_webrtc_send_pli(struct pss_webrtc *pss);

static struct lws_vhost *
lws_webrtc_get_vhost(struct vhd_webrtc *vhd)
{
	return vhd->vhost;
}

static struct lws_context *
lws_webrtc_get_context(struct vhd_webrtc *vhd)
{
	return vhd->context;
}

static uint8_t lws_webrtc_get_video_pt(struct pss_webrtc *pss) { return pss->pt_video; }
static uint8_t lws_webrtc_get_video_pt_h264(struct pss_webrtc *pss) { return pss->pt_video_h264; }
static uint8_t lws_webrtc_get_video_pt_av1(struct pss_webrtc *pss) { return pss->pt_video_av1; }
static uint16_t lws_webrtc_get_seq_video(struct pss_webrtc *pss) { return pss->last_seq_video; }
static uint8_t lws_webrtc_get_audio_pt(struct pss_webrtc *pss) { return pss->pt_audio; }

static void
lws_webrtc_set_on_media(struct vhd_webrtc *vhd, lws_webrtc_on_media_cb cb)
{
	vhd->on_media = cb;
}

static void
rtp_packet_tx_cb(void *priv, const uint8_t *pkt, size_t len, int marker)
{
	struct pss_webrtc *pss = (struct pss_webrtc *)priv;
	uint8_t protected_pkt[2048 + LWS_PRE];
	uint8_t *p = protected_pkt + LWS_PRE;
	size_t protected_len = len;

	(void)marker;

	if (!pss->has_peer_sin)
		return;

	memcpy(p, pkt, len);
	if (marker) p[1] |= 0x80;

	if (lws_srtp_protect(&pss->srtp_ctx_tx, p, &protected_len, 2048)) {
		lwsl_err("%s: SRTP protect failed\n", __func__);
		return;
	}

	/*
	 * Non-blocking send. If we get EAGAIN/ENOBUFS, we must drop the packet
	 * to avoid blocking the event loop or spinning.
	 */
	if (sendto(lws_get_socket_fd(pss->wsi_udp), (const char *)p, LWS_POSIX_LENGTH_CAST(protected_len), 0,
				(const struct sockaddr *)&pss->peer_sin, sizeof(pss->peer_sin)) < (int)protected_len) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS) {
			lwsl_err("%s: UDP sendto failed: %d (%s)\n", __func__, errno, strerror(errno));
		}
		/* Else: dropped (EAGAIN/ENOBUFS) */
	} else {
		if (!pss->sent_first_rtp) {
			lwsl_notice("%s: Sent FIRST RTP packet to peer\n", __func__);
			pss->sent_first_rtp = 1;
		}
		if (len > 50 && pss->sent_first_video < 10) {
			lwsl_notice("%s: Sent Video RTP pkt %d to peer (len %zu, marker %d)\n", __func__, pss->sent_first_video, protected_len, marker);
			pss->sent_first_video++;
		}
	}
}

/*
 * Public API for the plugin to be used by other components via pvo or similar.
 * Since this is a plugin, we might need a way to export these or use them
 * through the protocol private data.
 */


static void
rtp_packet_tx_cb_tracker(void *priv, const uint8_t *pkt, size_t len, int m)
{
	struct rtp_tx_tracker *t = (struct rtp_tx_tracker *)priv;
	t->count++;
	rtp_packet_tx_cb(t->pss, pkt, len, m);
}

static int
lws_webrtc_send_video(struct pss_webrtc *pss, const uint8_t *buf, size_t len, int codec, uint32_t pts)
{
	struct rtp_tx_tracker tracker = { pss, 0 };
	int is_av1 = 0;
	uint8_t pt = 0;

	if (!pss->handshake_done)
		return 0;

	if (codec == LWS_WEBRTC_CODEC_AV1) {
		is_av1 = 1;
		pt = pss->pt_video_av1;
	} else {
		is_av1 = 0;
		pt = pss->pt_video_h264;
	}

	if (!pt) {
		/* Participant doesn't support this codec */
		return 0;
	}

	if (pss->sent_first_video < 10)
		lwsl_notice("%s: Outgoing video session %p, len %zu, PT %u, SSRC %u, Codec %d\n",
				__func__, pss, len, pt, pss->ssrc_video, codec);

	if (!pss->rtp_ts_offset_set) {
		/* Lock the incoming master PTS to our randomized session timeline */
		pss->rtp_ts_offset = pss->rtp_ctx_video.ts - pts;
		pss->rtp_ts_offset_set = 1;
		lwsl_notice("%s: Session %p, Base TS %u, Master PTS %u, Sync Offset %u\n",
				__func__, pss, pss->rtp_ctx_video.ts, pts, pss->rtp_ts_offset);
	}

	pss->rtp_ctx_video.ts = pts + pss->rtp_ts_offset;

	// static int ts_tick = 0;
	// if (ts_tick++ % 100 == 0)
	// 	lwsl_notice("%s: Session %p, Codec %d, Master PTS %u -> Calced RTP TS %u (Handshake Done: %d)\n",
	// 		__func__, pss, codec, pts, pss->rtp_ctx_video.ts, pss->handshake_done);

	if (is_av1) {
		const uint8_t *src = buf, *end = buf + len;
		pss->rtp_ctx_video.pt = pt;

		static int av1_rx_cnt = 0;
		if (av1_rx_cnt++ % 50 == 0) {
			char hex[128], *ph = hex;
			size_t dlen = (len > 32 ? 32 : len);
			for (size_t i = 0; i < dlen; i++)
				ph += lws_snprintf(ph, 4, "%02x ", buf[i]);
			lwsl_notice("%s: Incoming AV1 Frame: len %zu, hex: %s\n", __func__, len, hex);
		}
		/* Lookahead scan: find the last valid OBU that we will actually transmit.
		 * We need this to correctly set the RTP 'marker' bit, which must be on
		 * the last packet of the last transmitted OBU of the Temporal Unit.
		 */
		const uint8_t *last_valid_obu = NULL;
		const uint8_t *scan = buf;
		while (scan < end) {
			uint8_t oh = *scan;
			int has_size = (oh & 0x02);
			const uint8_t *obu_start = scan;
			size_t pl = 0;
			scan++;
			if (oh & 0x04 && scan < end) scan++;
			if (has_size && scan < end) {
				const uint8_t *ts = scan;
				size_t tr = (size_t)(end - scan);
				uint32_t s = 0; int shift = 0;
				while (tr > 0) {
					uint8_t b = *ts++; tr--;
					s |= (uint32_t)(b & 0x7f) << shift;
					if (!(b & 0x80)) break;
					shift += 7;
				}
				scan = ts; pl = s;
			} else if (!has_size) {
				pl = (size_t)(end - scan);
			}
			uint8_t type = (oh >> 3) & 0x0f;

			// Debug: Print OBU type
			static int obu_log_limit = 0;
			if (obu_log_limit++ < 100) {
				lwsl_notice("%s: AV1 OBU Type %u, len %zu, has_size %d\n", __func__, type, pl, has_size);
			}

			if (type != 2 && type != 5 && type != 15)
				last_valid_obu = obu_start;

			if (pl > (size_t)(end - scan))
				pl = (size_t)(end - scan);
			scan += pl;
		}

		/* Parse Annex B OBUs from buf */
		while (src < end) {
			uint8_t oh = *src;
			int has_size = (oh & 0x02);
			const uint8_t *ps = NULL;
			size_t pl = 0;

			const uint8_t *obu_start = src;
			src++; /* Header */
			if (oh & 0x04 && src < end) src++; /* Extension */

			if (has_size && src < end) {
				const uint8_t *ts = src;
				size_t tr = (size_t)(end - src);
				uint32_t s = 0;
				int shift = 0;
				while (tr > 0) {
					uint8_t b = *ts++; tr--;
					s |= (uint32_t)(b & 0x7f) << shift;
					if (!(b & 0x80)) break;
					shift += 7;
				}
				src = ts;
				pl = s;
			} else if (!has_size) {
				pl = (size_t)(end - src);
			}

			if (pl > (size_t)(end - src)) pl = (size_t)(end - src);

			ps = src;
			uint8_t stack_obu[4096], *tmp_obu = NULL;
			uint8_t oh_no_size = (uint8_t)(oh & 0xfd);
			size_t tl = 1 + (oh & 0x04 ? 1 : 0);

			if (tl + pl <= sizeof(stack_obu)) {
				tmp_obu = stack_obu;
			} else {
				tmp_obu = malloc(tl + pl);
			}

			if (tmp_obu) {
				tmp_obu[0] = oh_no_size;
				if (oh & 0x04) tmp_obu[1] = obu_start[1];

				uint8_t type = (tmp_obu[0] >> 3) & 0x0f;
				if (type == 2 || type == 5 || type == 15) {
					/* RFC 9436: OBU type 2 (Temporal Delimiter) SHOULD be removed.
					 * OBU type 5 (Metadata) and 15 (Padding) can also confuse some decoders. */
					if (tmp_obu != stack_obu) free(tmp_obu);
					src += pl;
					continue;
				}

				// lwsl_notice("%s: Sending AV1 OBU type %d, len %zu (marker %d), hex: %02x %02x %02x %02x\n",
				//	__func__, type, pl, (obu_start == last_valid_obu),
				//	tmp_obu[0], tl > 1 ? tmp_obu[1] : 0, tmp_obu[tl], tmp_obu[tl+1]);

				memcpy(tmp_obu + tl, ps, pl);
				lws_rtp_av1_packetize(&pss->rtp_ctx_video, tmp_obu, tl + pl, (obu_start == last_valid_obu), LWS_RTP_MTU_DEFAULT, rtp_packet_tx_cb_tracker, &tracker);
				if (tmp_obu != stack_obu) free(tmp_obu);
			}

			src += pl;
		}
	} else {
		const uint8_t *p = buf, *end = buf + len;
		const uint8_t *nal_start = NULL;

		pss->rtp_ctx_video.pt = pt;

		while (p < end) {
			const uint8_t *next_nal = NULL;
			/* Find this NAL start */
			if (p + 3 < end && p[0] == 0 && p[1] == 0 && p[2] == 1) {
				nal_start = p + 3;
			} else if (p + 4 < end && p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 1) {
				nal_start = p + 4;
			} else {
				p++;
				continue;
			}

			/* Find next NAL start */
			const uint8_t *q = nal_start;
			while (q + 3 < end) {
				if (q[0] == 0 && q[1] == 0 && (q[2] == 1 || (q[2] == 0 && q[3] == 1))) {
					next_nal = q;
					break;
				}
				q++;
			}

			size_t nal_len = next_nal ? (size_t)(next_nal - nal_start) : (size_t)(end - nal_start);
			uint8_t type = nal_start[0] & 0x1f;
			int last = !next_nal;

			if (type == 7 || type == 8 || type == 5 || (pss->sent_first_video % 30 == 0))
				lwsl_debug("%s: Outgoing H264 NAL type %u, len %zu, SSRC %u, PT %u (last %d)\n", __func__, type, nal_len, pss->ssrc_video, pt, last);

			if (type == 7 && nal_len <= sizeof(pss->sps)) {
				memcpy(pss->sps, nal_start, nal_len);
				pss->sps_len = nal_len;
			} else if (type == 8 && nal_len <= sizeof(pss->pps)) {
				memcpy(pss->pps, nal_start, nal_len);
				pss->pps_len = nal_len;
			} else if (type == 5) {
				lws_usec_t now = lws_now_usecs();
				if (now - pss->last_sps_pps_ts > 1 * LWS_US_PER_SEC) {
					if (pss->sps_len)
						lws_rtp_h264_packetize(&pss->rtp_ctx_video, pss->sps, pss->sps_len, 0, LWS_RTP_MTU_DEFAULT, rtp_packet_tx_cb_tracker, &tracker);
					if (pss->pps_len)
						lws_rtp_h264_packetize(&pss->rtp_ctx_video, pss->pps, pss->pps_len, 0, LWS_RTP_MTU_DEFAULT, rtp_packet_tx_cb_tracker, &tracker);
					pss->last_sps_pps_ts = now;
				}
			}

			lws_rtp_h264_packetize(&pss->rtp_ctx_video, nal_start, nal_len, last, LWS_RTP_MTU_DEFAULT, rtp_packet_tx_cb_tracker, &tracker);

			if (next_nal)
				p = next_nal;
			else
				p = end;
		}
	}

	/* Increment timestamp: 90000Hz / 30fps = 3000 (Global for all codecs) */
	pss->rtp_ctx_video.ts += 3000;

	// if (pss->sent_first_video < 20) {
	//	lwsl_notice("%s: Sent frame (len %zu, packets %d, Codec %d, PT %u, TS %u)\n",
	//		__func__, len, tracker.count, codec, pss->rtp_ctx_video.pt, pss->rtp_ctx_video.ts);
	// }

	pss->sent_first_video++;
	if (pss->sent_first_video > 1000) pss->sent_first_video = 100; /* throttle but stay tracking */

	return 0;
}

static int
lws_webrtc_send_audio(struct pss_webrtc *pss, const uint8_t *buf, size_t len, uint32_t timestamp)
{
	uint8_t pkt[1514 + LWS_PRE];
	uint8_t *p = pkt + LWS_PRE;
	size_t pkt_len = LWS_RTP_HEADER_LEN + len;

	if (!pss->handshake_done)
		return 0;

	if (timestamp != 0) {
		if (!pss->rtp_ts_audio_offset_set) {
			pss->rtp_ts_audio_offset = pss->rtp_ctx_audio.ts - timestamp;
			pss->rtp_ts_audio_offset_set = 1;
		}
		pss->rtp_ctx_audio.ts = timestamp + pss->rtp_ts_audio_offset;
	}

	lws_rtp_write_header(&pss->rtp_ctx_audio, p, 0); /* Marker=0 for audio */
	memcpy(p + LWS_RTP_HEADER_LEN, buf, len);

	if (timestamp == 0)
		pss->rtp_ctx_audio.ts += 960; /* Use fallback for 20ms if PTS omitted */

	if (lws_srtp_protect(&pss->srtp_ctx_tx, p, &pkt_len, 1514) == 0) {
		if (!pss->sent_first_audio) {
			lwsl_notice("%s: Sent FIRST Audio RTP packet to peer (PT %u, SSRC %u, len %zu)\n",
					__func__, pss->rtp_ctx_audio.pt, pss->rtp_ctx_audio.ssrc, pkt_len);
			pss->sent_first_audio = 1;
		}
		sendto(lws_get_socket_fd(pss->wsi_udp), (const char *)p, LWS_POSIX_LENGTH_CAST(pkt_len), 0,
				(const struct sockaddr *)&pss->peer_sin, sizeof(pss->peer_sin));
		return 0;
	}

	return 0;
}

static int
lws_webrtc_send_text(struct pss_webrtc *pss, const char *buf, size_t len)
{
	if (lws_buflist_append_segment(&pss->buflist, (const uint8_t *)buf, len) < 0)
		return -1;

	lws_callback_on_writable(pss->wsi_ws);

	return (int)len;
}

static int
lws_webrtc_send_pli(struct pss_webrtc *pss)
{
	uint8_t pli[128 + LWS_PRE];
	uint8_t *p = pli + LWS_PRE;

	if (!pss->ssrc_peer_video) return 0;

	/* RTCP PLI: Vers=2, P=0, FMT=1, PT=206, Len=2 (12 bytes) */
	p[0] = 0x81; p[1] = 206; p[2] = 0; p[3] = 2;
	/* SSRC of sender */
	p[4] = (uint8_t)(pss->ssrc_video >> 24); p[5] = (uint8_t)(pss->ssrc_video >> 16);
	p[6] = (uint8_t)(pss->ssrc_video >> 8);  p[7] = (uint8_t)pss->ssrc_video;
	/* SSRC of media source (browser) */
	p[8] = (uint8_t)(pss->ssrc_peer_video >> 24); p[9] = (uint8_t)(pss->ssrc_peer_video >> 16);
	p[10] = (uint8_t)(pss->ssrc_peer_video >> 8); p[11] = (uint8_t)pss->ssrc_peer_video;

	size_t len = 12;
	if (lws_srtp_protect_rtcp(&pss->srtp_ctx_tx, p, &len, sizeof(pli) - LWS_PRE) == 0) {
		lwsl_notice("%s: Sending PLI request for SSRC %u\n", __func__, pss->ssrc_peer_video);
		sendto(lws_get_socket_fd(pss->wsi_udp), (const char *)p, LWS_POSIX_LENGTH_CAST(len), 0, (const struct sockaddr *)&pss->peer_sin, sizeof(pss->peer_sin));
	}
	return 0;
}

static int
lws_webrtc_create_offer(struct pss_webrtc *pss)
{
	struct vhd_webrtc *vhd;
	const struct lws_protocols *prot = lws_vhost_name_to_protocol(lws_get_vhost(pss->wsi_ws), "lws-webrtc");
	if (!prot) return -1;
	vhd = (struct vhd_webrtc *)lws_protocol_vh_priv_get(lws_get_vhost(pss->wsi_ws), prot);
	char json_buf[LWS_PRE + 8192], *p = &json_buf[LWS_PRE];
	char audio_m[2048], video_m[2048], candidates[1024] = "";
	size_t n_sdp;

	pss->is_client = 1;

	if (!vhd) return -1;

	/* Initialize Client DTLS */
	if (!pss->handshake_started) {
		struct lws_gendtls_creation_info ci;
		memset(&ci, 0, sizeof(ci));
		ci.context = vhd->context;
		ci.mode = LWS_GENDTLS_MODE_CLIENT;
		ci.mtu = 1100;
		ci.use_srtp = "SRTP_AES128_CM_SHA1_80";
		if (lws_gendtls_create(&pss->dtls_ctx, &ci)) return -1;
		lws_gendtls_set_cert_mem(&pss->dtls_ctx, vhd->cert_mem, vhd->cert_len);
		lws_gendtls_set_key_mem(&pss->dtls_ctx, vhd->key_mem, vhd->key_len);
		pss->handshake_started = 1;
		pss->wsi_udp = vhd->wsi_udp;
	}

	/* Default PTs for Offer */
	pss->pt_audio = 111;
	pss->pt_video = 100; /* VP8? No, let's use dynamic */
	pss->pt_video_h264 = 102;
	pss->pt_video_av1 = 104;
	pss->pt_video = pss->pt_video_h264; /* Default to H264 */

	pss->rtp_ctx_video.ts = (uint32_t)(lws_now_usecs() * 9 / 100);
	pss->rtp_ctx_audio.ts = (uint32_t)(lws_now_usecs() * 48 / 1000);

	lws_rtp_init(&pss->rtp_ctx_video, pss->ssrc_video, pss->pt_video);
	lws_rtp_init(&pss->rtp_ctx_audio, pss->ssrc_audio, pss->pt_audio);

	/* Candidates */
	if (vhd->external_ip[0]) {
		lws_snprintf(candidates, sizeof(candidates),
				"a=candidate:1 1 UDP 2130706431 %s %u typ host\\r\\n",
				vhd->external_ip, vhd->udp_port);
	} else {
		lws_snprintf(candidates, sizeof(candidates),
				"a=candidate:1 1 UDP 2130706431 127.0.0.1 %u typ host\\r\\n",
				vhd->udp_port);
	}

	/* Video Section */
	lws_snprintf(video_m, sizeof(video_m),
			"m=video %u UDP/TLS/RTP/SAVPF %u %u\\r\\n"
			"c=IN IP4 0.0.0.0\\r\\n"
			"a=rtcp-mux\\r\\n"
			"a=ice-ufrag:%s\\r\\n"
			"a=ice-pwd:%s\\r\\n"
			"a=fingerprint:sha-256 %s\\r\\n"
			"a=setup:actpass\\r\\n"
			"a=mid:1\\r\\n"
			"a=sendonly\\r\\n"
			"a=msid:lws-stream lws-track-video\\r\\n"
			"a=rtpmap:%u H264/90000\\r\\n"
			"a=fmtp:%u level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42c01f\\r\\n"
			"a=rtpmap:%u AV1/90000\\r\\n"
			"a=fmtp:%u profile=0;level-idx=5;tier=0\\r\\n"
			"a=rtcp-fb:%u nack\\r\\n"
			"a=rtcp-fb:%u nack pli\\r\\n"
			"a=rtcp-fb:%u nack\\r\\n"
			"a=rtcp-fb:%u nack pli\\r\\n"
			"a=ssrc:%u cname:lws-video\\r\\n"
			"a=ssrc:%u msid:lws-stream lws-track-video\\r\\n"
			"%s"
			"a=end-of-candidates\\r\\n",
		vhd->udp_port, pss->pt_video_h264, pss->pt_video_av1,
		pss->ice_ufrag, pss->ice_pwd, vhd->fingerprint,
		pss->pt_video_h264, pss->pt_video_h264,
		pss->pt_video_av1, pss->pt_video_av1,
		pss->pt_video_h264, pss->pt_video_h264,
		pss->pt_video_av1, pss->pt_video_av1,
		pss->ssrc_video, pss->ssrc_video, candidates);

	/* Audio Section */
	lws_snprintf(audio_m, sizeof(audio_m),
			"m=audio %u UDP/TLS/RTP/SAVPF %u\\r\\n"
			"c=IN IP4 0.0.0.0\\r\\n"
			"a=rtcp-mux\\r\\n"
			"a=ice-ufrag:%s\\r\\n"
			"a=ice-pwd:%s\\r\\n"
			"a=fingerprint:sha-256 %s\\r\\n"
			"a=setup:actpass\\r\\n"
			"a=mid:0\\r\\n"
			"a=sendonly\\r\\n"
			"a=msid:lws-stream lws-track-audio\\r\\n"
			"a=rtpmap:%u opus/48000/2\\r\\n"
			"a=fmtp:%u maxplaybackrate=48000;sprop-stereo=0;stereo=0;useinbandfec=0;maxaveragebitrate=20000\\r\\n"
			"a=ssrc:%u cname:lws-audio\\r\\n"
			"a=ssrc:%u msid:lws-stream lws-track-audio\\r\\n"
			"%s"
			"a=end-of-candidates\\r\\n",
			vhd->udp_port, pss->pt_audio,
			pss->ice_ufrag, pss->ice_pwd, vhd->fingerprint,
			pss->pt_audio, pss->pt_audio,
			pss->ssrc_audio, pss->ssrc_audio, candidates);

	n_sdp = (size_t)lws_snprintf(p, 8192,
			"{\"type\":\"offer\",\"sdp\":\"v=0\\r\\no=- 123456 2 IN IP4 %s\\r\\ns=-\\r\\nt=0 0\\r\\na=msid-semantic: WMS lws-stream\\r\\na=ice-lite\\r\\na=group:BUNDLE 0 1\\r\\n%s%s\"}",
			vhd->external_ip[0] ? vhd->external_ip : "127.0.0.1", audio_m, video_m);

	lwsl_notice("%s: Generated OFFER (%zu bytes)\n", __func__, n_sdp);
	write(2, "\n--- START SDP OFFER ---\n", 25);
	write(2, p, n_sdp);
	write(2, "\n--- END SDP OFFER ---\n\n", 25);

	if (lws_buflist_append_segment(&pss->buflist, (const uint8_t *)p, n_sdp) < 0)
		return -1;
	lws_callback_on_writable(pss->wsi_ws);

	return 0;
}

/* STUN Binding Request generator */
static int
lws_webrtc_stun_req_pack(struct pss_webrtc *pss, uint8_t *buf, size_t len, uint8_t *tid)
{
	uint8_t *start = buf, *p = buf + 20;
	uint32_t magic = LWS_STUN_MAGIC_COOKIE;
	char username[128];
	int user_len;
	struct lws_genhmac_ctx hmac_ctx;
	uint8_t hmac[20];
	uint32_t fp;

	/* Header: Type 0x0001 (Binding Request) */
	lws_ser_wu16be(buf, 0x0001);
	/* Length (filled later) */
	lws_ser_wu16be(buf + 2, 0);
	/* Magic Cookie */
	lws_ser_wu32be(buf + 4, magic);
	/* Transaction ID */
	memcpy(buf + 8, tid, 12);

	/* 1. USERNAME (0x0006): remote_ufrag:local_ufrag */
	user_len = lws_snprintf(username, sizeof(username), "%s:%s", pss->ice_ufrag_remote, pss->ice_ufrag);
	if (user_len > 0) {
		lws_ser_wu16be(p, LWS_STUN_ATTR_USERNAME);
		lws_ser_wu16be(p + 2, (uint16_t)user_len);
		memcpy(p + 4, username, (size_t)user_len);
		p += 4 + user_len;
		/* Padding to 4 bytes */
		while ((p - start) & 3) *p++ = 0;
	}

	/* 2. PRIORITY (0x0024) */
	lws_ser_wu16be(p, 0x0024);
	lws_ser_wu16be(p + 2, 4);
	lws_ser_wu32be(p + 4, 1845494271); /* Type preference 110, Local pref 65535, Component 255 */
	p += 8;

	/* 3. ICE-CONTROLLING (0x802A) */
	lws_ser_wu16be(p, 0x802A);
	lws_ser_wu16be(p + 2, 8);
	lws_get_random(lws_get_context(pss->wsi_ws), p + 4, 8);
	p += 12;

	/* 4. MESSAGE-INTEGRITY (0x0008) */
	/* Should use remote password */
	if (pss->ice_pwd_remote[0]) {
		uint16_t msg_len = (uint16_t)(p - start - 20 + 24); /* Current len + attribute header + HMAC (20) */
		lws_ser_wu16be(start + 2, msg_len);

		if (lws_genhmac_init(&hmac_ctx, LWS_GENHMAC_TYPE_SHA1, (uint8_t *)pss->ice_pwd_remote, strlen(pss->ice_pwd_remote)) ||
				lws_genhmac_update(&hmac_ctx, start, (size_t)(p - start)) ||
				lws_genhmac_destroy(&hmac_ctx, hmac)) {
			lwsl_err("%s: HMAC failed\n", __func__);
			return -1;
		}

		lws_ser_wu16be(p, 0x0008);
		lws_ser_wu16be(p + 2, 20);
		memcpy(p + 4, hmac, 20);
		p += 24;
	}

	/* 5. FINGERPRINT (0x8028) */
	{
		uint16_t msg_len = (uint16_t)(p - start - 20 + 8); /* Current len + attribute header + CRC (4) */
		lws_ser_wu16be(start + 2, msg_len);

		fp = lws_crc32(0, start, (size_t)(p - start));
		fp ^= LWS_STUN_FINGERPRINT_XOR;

		lws_ser_wu16be(p, 0x8028);
		lws_ser_wu16be(p + 2, 4);
		lws_ser_wu32be(p + 4, fp);
		p += 8;
	}

	/* Update Header Length (Payload length) */
	lws_ser_wu16be(start + 2, (uint16_t)(p - start - 20));

	return (int)(p - start);
}


	static int
handle_candidate(struct pss_webrtc *pss, struct vhd_webrtc *vhd, const char *cand)
{
	char ip_str[64];
	int port = 0;
	struct lws_tokenize ts;

	/*
	 * Format: candidate:1 1 UDP <prio> <IP> <PORT> ...
	 * We need to handle "candidate:1" or "candidate" "1" depending on tokenizer.
	 * Let's just look for "UDP" then take the next 3 tokens: priority, IP, port.
	 */
	lws_tokenize_init(&ts, cand, LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_DOT_NONTERM);
	ts.len = strlen(cand);

	int state = 0;

	while (lws_tokenize(&ts) != LWS_TOKZE_ENDED) {
		lwsl_notice("%s: Token: '%.*s' (len %d, type %d), state %d\n", __func__, (int)ts.token_len, ts.token, (int)ts.token_len, ts.e, state);
		if (state == 0 && ts.token_len == 3 && !strncmp(ts.token, "UDP", 3)) {
			state = 1; /* Found Protocol UDP */
		} else if (state == 1) {
			/* Priority */
			state = 2;
		} else if (state == 2) {
			/* IP Address */
			if (ts.token_len < sizeof(ip_str)) {
				lws_strncpy(ip_str, ts.token, sizeof(ip_str));
				state = 3;
			} else {
				return -1;
			}
		} else if (state == 3) {
			/* Port */
			port = atoi(ts.token);
			state = 5;
			break;
		}
	}

	if (state == 5 && port > 0) {
		lwsl_notice("%s: Found Candidate: %s:%d\n", __func__, ip_str, port);

		memset(&pss->peer_sin, 0, sizeof(pss->peer_sin));
		pss->peer_sin.sin_family = AF_INET;
		pss->peer_sin.sin_port = htons((uint16_t)port);
		inet_pton(AF_INET, ip_str, &pss->peer_sin.sin_addr);
		pss->has_peer_sin = 1;

		/* Send STUN Binding Request to punch hole */
		uint8_t stun[2048];
		uint8_t tid[12];

		if (!pss->wsi_udp) {
			lwsl_err("%s: Error: pss->wsi_udp is NULL!\n", __func__);
			return -1;
		}

		lws_get_random(vhd->context, tid, 12);
		int n = lws_webrtc_stun_req_pack(pss, stun, sizeof(stun), tid);
		if (n > 0) {
			sendto(lws_get_socket_fd(pss->wsi_udp), (const char *)stun, (size_t)n, 0,
					(const struct sockaddr *)&pss->peer_sin, sizeof(pss->peer_sin));
			lwsl_notice("%s: Sent STUN Binding Request to %s:%d\n", __func__, ip_str, port);
		} else {
			lwsl_err("%s: lws_stun_req_pack failed: %d\n", __func__, n);
		}
		return 0;
	}

	return 0;
}

static void
lws_webrtc_parse_sdp_codecs(struct pss_webrtc *pss, const char *sdp_clean)
{
	/* Reset PSS PTs */
	pss->pt_audio = 0;
	pss->pt_video_h264 = 0;
	pss->pt_video_av1 = 0;
	pss->pt_video = 0;

	char mid_audio[32] = "0", mid_video[32] = "1";
	int audio_first = 0;

	/* Quick scan for order using strstr as it's efficient for this high-level check */
	const char *p_audio = strstr(sdp_clean, "m=audio");
	const char *p_video = strstr(sdp_clean, "m=video");

	if (p_audio && p_video && p_audio < p_video)
		audio_first = 1;

	(void)audio_first; /* suppress unused-but-set-variable */

	char *p_scan = (char *)sdp_clean;
	int in_audio = 0;
	int in_video = 0;

	/* H.264 PT Map */
	uint8_t h264_pt_map[128];
	memset(h264_pt_map, 0, sizeof(h264_pt_map));

	/* Pass 1: Build H.264 PT Map from rtpmap */
	char *p_pass1 = (char *)sdp_clean;
	while (*p_pass1) {
		char *eol = strchr(p_pass1, '\n');
		size_t line_len = eol ? (size_t)(eol - p_pass1) : strlen(p_pass1);
		if (line_len > 0 && p_pass1[line_len-1] == '\r') line_len--;

		/* We only care about a=rtpmap here */
		if (line_len > 9 && !strncmp(p_pass1, "a=rtpmap:", 9)) {
			char line[256]; /* Sufficient for rtpmap */
			if (line_len < sizeof(line)) {
				memcpy(line, p_pass1, line_len);
				line[line_len] = '\0';

				struct lws_tokenize ts;
				lws_tokenize_init(&ts, line, LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_SLASH_NONTERM);
				ts.len = line_len;

				/* Skip "a=rtpmap:" part by finding first integer */
				int pt = -1;
				while (lws_tokenize(&ts) != LWS_TOKZE_ENDED) {
					if (ts.token_len > 0 && isdigit(ts.token[0])) {
						pt = atoi(ts.token);
						break; /* Found PT */
					}
				}

				if (pt != -1 && pt < 128) {
					/* Next token should be Codec/Rate */
					if (lws_tokenize(&ts) == LWS_TOKZE_TOKEN) {
						if (!strncasecmp(ts.token, "H264/90000", 10)) {
							h264_pt_map[pt] = 1;
						}
					}
				}
			}
		}

		if (!eol) break;
		p_pass1 = eol + 1;
	}

	/* Pass 2: Main Parsing */
	while (*p_scan) {
		char *eol = strchr(p_scan, '\n');
		size_t line_len = eol ? (size_t)(eol - p_scan) : strlen(p_scan);
		if (line_len > 0 && p_scan[line_len-1] == '\r') line_len--;

		/* Create separate buffer for line to tokenize safely */
		char line[1024];
		if (line_len < sizeof(line)) {
			memcpy(line, p_scan, line_len);
			line[line_len] = '\0';

			if (!strncmp(line, "m=audio", 7)) { in_audio = 1; in_video = 0; }
			else if (!strncmp(line, "m=video", 7)) { in_audio = 0; in_video = 1; }

			if (in_audio && !strncmp(line, "a=mid:", 6)) {
				lws_strncpy(mid_audio, line + 6, sizeof(mid_audio));
			}
			if (in_video && !strncmp(line, "a=mid:", 6)) {
				lws_strncpy(mid_video, line + 6, sizeof(mid_video));
			}

			/* Parse RTP Maps and FMTPs */
			/* a=rtpmap:<pt> <codec>/<rate> */
			if (!strncmp(line, "a=rtpmap:", 9)) {
				struct lws_tokenize ts;
				lws_tokenize_init(&ts, line, LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_SLASH_NONTERM);
				ts.len = line_len;

				/* Skip "a=rtpmap:" part by finding first integer */
				int pt = -1;
				while (lws_tokenize(&ts) != LWS_TOKZE_ENDED) {
					if (ts.token_len > 0 && isdigit(ts.token[0])) {
						pt = atoi(ts.token);
						break; /* Found PT */
					}
				}

				if (pt != -1) {
					/* Next token should be Codec/Rate */
					if (lws_tokenize(&ts) == LWS_TOKZE_TOKEN) {
						if (!strncasecmp(ts.token, "H264/90000", 10)) {
							/* We found H264. Map already populated in Pass 1. */
						} else if (!strncasecmp(ts.token, "AV1/90000", 9)) {
							pss->pt_video_av1 = (uint8_t)pt;
						} else if (!strncasecmp(ts.token, "VP9/90000", 9)) {
						} else if (!strncasecmp(ts.token, "opus/48000", 10)) {
							pss->pt_audio = (uint8_t)pt;
						}
					}
				}
			}

			/* a=fmtp:<pt> ... */
			if (!strncmp(line, "a=fmtp:", 7)) {
				struct lws_tokenize ts;
				lws_tokenize_init(&ts, line, LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_EQUALS_NONTERM);
				ts.len = line_len;

				int pt = -1;
				/* Find PT first */
				while (lws_tokenize(&ts) != LWS_TOKZE_ENDED) {
					if (ts.token_len > 0 && isdigit(ts.token[0])) {
						pt = atoi(ts.token);
						break;
					}
				}

				if (pt != -1) {
					/* Check if this is H264 Mode 1 */
					if (!pss->pt_video_h264) {
						int is_mode_1 = 0;
						while (lws_tokenize(&ts) != LWS_TOKZE_ENDED) {
							if (ts.token_len == 18 && !strncmp(ts.token, "packetization-mode", 18)) {
								/* Next token should be = then 1 */
								if (lws_tokenize(&ts) == LWS_TOKZE_DELIMITER && ts.token[0] == '=') {
									if (lws_tokenize(&ts) == LWS_TOKZE_INTEGER && ts.token[0] == '1') {
										is_mode_1 = 1;
									}
								}
							}
						}

						if (is_mode_1) {
							pss->pt_video_h264 = (uint8_t)pt;
						} else {
							/* Only accept if we verified it is H264 via rtpmap */
							if (pt < 128 && h264_pt_map[pt]) {
								/* If we haven't found a better one (Mode 1), use this */
								if (!pss->pt_video_h264)
									pss->pt_video_h264 = (uint8_t)pt;
							}
						}
					}

					/* Capture FMTP for Audio/Video */
					if (pt == pss->pt_audio) {
						if (strlen(line) - 7 > 0) {
							const char *fmtp_val = strchr(line, ' '); /* Skip a=fmtp:<pt> */
							if (fmtp_val) {
								while (*fmtp_val == ' ') fmtp_val++;
								lws_strncpy(pss->fmtp_audio, fmtp_val, sizeof(pss->fmtp_audio));
							}
						}
					} else if (pt == pss->pt_video_av1 || pt == pss->pt_video_h264) {
						if (strlen(line) - 7 > 0) {
							const char *fmtp_val = strchr(line, ' ');
							if (fmtp_val) {
								while (*fmtp_val == ' ') fmtp_val++;
								lws_strncpy(pss->fmtp_video, fmtp_val, sizeof(pss->fmtp_video));
							}
						}
					}
				}
			}
		}

		if (!eol) break;
		p_scan = eol + 1;
	}

	/* Defaults */
	if (pss->pt_audio == 0) pss->pt_audio = 111;
	if (pss->pt_video_h264 == 0) pss->pt_video_h264 = 0; /* No H264 found */

	/* Preference: H264 > AV1 */
	pss->pt_video = pss->pt_video_h264 ? pss->pt_video_h264 : pss->pt_video_av1;
	if (pss->pt_video == 0) pss->pt_video = 126; /* Fallback? */

	lwsl_notice("%s: Negotiated PTs: Audio=%u, Video=%u (H264=%u, AV1=%u)\n",
			__func__, pss->pt_audio, pss->pt_video, pss->pt_video_h264, pss->pt_video_av1);
}

static int
handle_answer(struct lws *wsi, struct pss_webrtc *pss, struct vhd_webrtc *vhd, const char *in, size_t len)

{
	lwsl_notice("%s: Matched 'answer'\n", __func__);

	/* Unescape JSON similar to handle_offer */
	size_t sdp_len = len;
	char *sdp_clean = calloc(1, sdp_len + 1);
	if (!sdp_clean) return -1;

	const char *src = (const char *)in;
	const char *src_end = src + len;
	char *dst = sdp_clean;

	while (src < src_end) {
		if (*src == '\\' && (src + 1 < src_end)) {
			if (src[1] == 'r') { src += 2; *dst++ = '\r'; }
			else if (src[1] == 'n') { src += 2; *dst++ = '\n'; }
			else if (src[1] == '"') { src += 2; *dst++ = '"'; }
			else *dst++ = *src++;
		} else {
			*dst++ = *src++;
		}
	}
	*dst = '\0';

	char *p = sdp_clean;
	while (*p) {
		char *eol = strchr(p, '\n');
		size_t line_len = eol ? (size_t)(eol - p) : strlen(p);
		if (line_len > 0 && p[line_len-1] == '\r') line_len--;

		if (line_len > 12 && !strncmp(p, "a=ice-ufrag:", 12)) {
			if (line_len - 12 < sizeof(pss->ice_ufrag_remote)) {
				memcpy(pss->ice_ufrag_remote, p + 12, line_len - 12);
				pss->ice_ufrag_remote[line_len - 12] = '\0';
				lwsl_notice("  Remote ICE Ufrag: %s\n", pss->ice_ufrag_remote);
			}
		} else if (line_len > 10 && !strncmp(p, "a=ice-pwd:", 10)) {
			if (line_len - 10 < sizeof(pss->ice_pwd_remote)) {
				memcpy(pss->ice_pwd_remote, p + 10, line_len - 10);
				pss->ice_pwd_remote[line_len - 10] = '\0';
				lwsl_notice("  Remote ICE Pwd: %s\n", pss->ice_pwd_remote);
			}
		} else if (line_len > 22 && !strncmp(p, "a=fingerprint:sha-256 ", 22)) {
			if (line_len - 22 < sizeof(pss->fingerprint_remote)) {
				memcpy(pss->fingerprint_remote, p + 22, line_len - 22);
				pss->fingerprint_remote[line_len - 22] = '\0';
				lwsl_notice("  Remote Fingerprint: %s\n", pss->fingerprint_remote);
			}
		} else if (line_len > 12 && !strncmp(p, "a=candidate:", 12)) {
			/* Create a null-terminated string for this line to pass to tokenizer */
			char line_copy[1024];
			if (line_len < sizeof(line_copy)) {
				memcpy(line_copy, p, line_len);
				line_copy[line_len] = '\0';
				handle_candidate(pss, vhd, line_copy);
			}
		}

		if (!eol) break;
		p = eol + 1;
	}

	lws_webrtc_parse_sdp_codecs(pss, sdp_clean);

	free(sdp_clean);

	/* Trigger DTLS Client Hello */
	lwsl_notice("%s: Checking DTLS Cond: started %d, done %d, peer %d\n", __func__, pss->handshake_started, pss->handshake_done, pss->has_peer_sin);
	if (pss->handshake_started && !pss->handshake_done && pss->has_peer_sin) {
		uint8_t dummy;
		lws_gendtls_get_rx(&pss->dtls_ctx, &dummy, 1);
		uint8_t out[2048];
		int _tx_len;
		while ((_tx_len = lws_gendtls_get_tx(&pss->dtls_ctx, out, sizeof(out))) > 0) {
			lwsl_notice("%s: Sending Initial DTLS ClientHello (%d bytes)\n", __func__, _tx_len);
			sendto(lws_get_socket_fd(pss->wsi_udp), (const char *)out, (size_t)_tx_len, 0, (const struct sockaddr *)&pss->peer_sin, sizeof(pss->peer_sin));
		}
	}

	return 0;
}

static int
handle_offer(struct lws *wsi, struct pss_webrtc *pss, struct vhd_webrtc *vhd, const char *in, size_t len)
{
	lwsl_user("Matched 'offer', generating answer\n");

	/* Unescape JSON */
	size_t sdp_len = len;
	char *sdp_clean = calloc(1, sdp_len + 1);
	if (!sdp_clean) {
		lwsl_err("%s: OOM unescaping SDP\n", __func__);
		return -1;
	}

	const char *src = (const char *)in;
	const char *src_end = src + len;
	char *dst = sdp_clean;

	while (src < src_end) {
		if (*src == '\\' && (src + 1 < src_end)) {
			if (src[1] == 'r') { src += 2; *dst++ = '\r'; }
			else if (src[1] == 'n') { src += 2; *dst++ = '\n'; }
			else if (src[1] == '"') { src += 2; *dst++ = '"'; }
			else *dst++ = *src++;
		} else {
			*dst++ = *src++;
		}
	}
	*dst = '\0';

	write(2, sdp_clean, strlen(sdp_clean));

	/* Reset PSS PTs */
	pss->pt_audio = 0;
	pss->pt_video_h264 = 0;
	pss->pt_video_av1 = 0;
	pss->pt_video = 0;

	char mid_audio[32] = "0", mid_video[32] = "1";
	int audio_first = 0;

	/* Quick scan for order using strstr as it's efficient for this high-level check */
	const char *p_audio = strstr(sdp_clean, "m=audio");
	const char *p_video = strstr(sdp_clean, "m=video");

	if (p_audio && p_video && p_audio < p_video)
		audio_first = 1;

	lwsl_notice("%s: SDP audio_first=%d\n", __func__, audio_first);

	char *p_scan = sdp_clean;
	int in_audio = 0;
	int in_video = 0;

	/* H.264 PT Map */
	uint8_t h264_pt_map[128];
	memset(h264_pt_map, 0, sizeof(h264_pt_map));

	/* Pass 1: Build H.264 PT Map from rtpmap */
	char *p_pass1 = sdp_clean;
	while (*p_pass1) {
		char *eol = strchr(p_pass1, '\n');
		size_t line_len = eol ? (size_t)(eol - p_pass1) : strlen(p_pass1);
		if (line_len > 0 && p_pass1[line_len-1] == '\r') line_len--;

		/* We only care about a=rtpmap here */
		if (line_len > 9 && !strncmp(p_pass1, "a=rtpmap:", 9)) {
			char line[256]; /* Sufficient for rtpmap */
			if (line_len < sizeof(line)) {
				memcpy(line, p_pass1, line_len);
				line[line_len] = '\0';

				struct lws_tokenize ts;
				lws_tokenize_init(&ts, line, LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_SLASH_NONTERM);
				ts.len = line_len;

				/* Skip "a=rtpmap:" part by finding first integer */
				int pt = -1;
				while (lws_tokenize(&ts) != LWS_TOKZE_ENDED) {
					if (ts.token_len > 0 && isdigit(ts.token[0])) {
						pt = atoi(ts.token);
						break; /* Found PT */
					}
				}

				if (pt != -1 && pt < 128) {
					/* Next token should be Codec/Rate */
					if (lws_tokenize(&ts) == LWS_TOKZE_TOKEN) {
						if (!strncasecmp(ts.token, "H264/90000", 10)) {
							h264_pt_map[pt] = 1;
						}
					}
				}
			}
		}

		if (!eol) break;
		p_pass1 = eol + 1;
	}

	/* Pass 2: Main Parsing */
	while (*p_scan) {
		char *eol = strchr(p_scan, '\n');
		size_t line_len = eol ? (size_t)(eol - p_scan) : strlen(p_scan);
		if (line_len > 0 && p_scan[line_len-1] == '\r') line_len--;

		/* Create separate buffer for line to tokenize safely */
		char line[1024];
		if (line_len < sizeof(line)) {
			memcpy(line, p_scan, line_len);
			line[line_len] = '\0';

			if (!strncmp(line, "m=audio", 7)) { in_audio = 1; in_video = 0; }
			else if (!strncmp(line, "m=video", 7)) { in_audio = 0; in_video = 1; }

			if (in_audio && !strncmp(line, "a=mid:", 6)) {
				lws_strncpy(mid_audio, line + 6, sizeof(mid_audio));
			}
			if (in_video && !strncmp(line, "a=mid:", 6)) {
				lws_strncpy(mid_video, line + 6, sizeof(mid_video));
			}

			/* Parse RTP Maps and FMTPs */
			/* a=rtpmap:<pt> <codec>/<rate> */
			if (!strncmp(line, "a=rtpmap:", 9)) {
				struct lws_tokenize ts;
				lws_tokenize_init(&ts, line, LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_SLASH_NONTERM);
				ts.len = line_len;

				/* ... (rest of main loop) ... */

				/* Skip "a=rtpmap:" part by finding first integer */
				int pt = -1;
				while (lws_tokenize(&ts) != LWS_TOKZE_ENDED) {
					if (ts.token_len > 0 && isdigit(ts.token[0])) {
						pt = atoi(ts.token);
						break; /* Found PT */
					}
				}

				if (pt != -1) {
					/* Next token should be Codec/Rate */
					if (lws_tokenize(&ts) == LWS_TOKZE_TOKEN) {
						lwsl_warn("  SDP Parsing: PT %d -> Token '%.*s'\n", pt, (int)ts.token_len, ts.token);
						if (!strncasecmp(ts.token, "H264/90000", 10)) {
							/* We found H264. Map already populated in Pass 1. */
						} else if (!strncasecmp(ts.token, "AV1/90000", 9)) {
							pss->pt_video_av1 = (uint8_t)pt;
							lwsl_info("  Found AV1 PT: %d\n", pt);
						} else if (!strncasecmp(ts.token, "VP9/90000", 9)) {
							lwsl_warn("  Found VP9 PT: %d. We DO NOT support VP9! Please use H264 or AV1.\n", pt);
						} else if (!strncasecmp(ts.token, "opus/48000", 10)) {
							pss->pt_audio = (uint8_t)pt;
							lwsl_info("  Found Opus PT: %d\n", pt);
						}
					}
				}
			}

			/* a=fmtp:<pt> ... */
			if (!strncmp(line, "a=fmtp:", 7)) {
				struct lws_tokenize ts;
				lws_tokenize_init(&ts, line, LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_EQUALS_NONTERM);
				ts.len = line_len;

				int pt = -1;
				/* Find PT first */
				while (lws_tokenize(&ts) != LWS_TOKZE_ENDED) {
					if (ts.token_len > 0 && isdigit(ts.token[0])) {
						pt = atoi(ts.token);
						break;
					}
				}

				if (pt != -1) {
					/* Check if this is H264 Mode 1 */
					if (!pss->pt_video_h264) {
						int is_mode_1 = 0;
						while (lws_tokenize(&ts) != LWS_TOKZE_ENDED) {
							if (ts.token_len == 18 && !strncmp(ts.token, "packetization-mode", 18)) {
								/* Next token should be = then 1 */
								if (lws_tokenize(&ts) == LWS_TOKZE_DELIMITER && ts.token[0] == '=') {
									if (lws_tokenize(&ts) == LWS_TOKZE_INTEGER && ts.token[0] == '1') {
										is_mode_1 = 1;
									}
								}
							}
						}

						if (is_mode_1) {
							pss->pt_video_h264 = (uint8_t)pt;
							lwsl_info("  Found H264 PT %d (Mode 1)\n", pt);
						} else {
							/* Only accept if we verified it is H264 via rtpmap */
							if (pt < 128 && h264_pt_map[pt]) {
								lwsl_warn("  Found H264 PT %d (Mode 0 / Implicit). Accepting.\n", pt);
								/* If we haven't found a better one (Mode 1), use this */
								if (!pss->pt_video_h264)
									pss->pt_video_h264 = (uint8_t)pt;
							}
						}
					}

					/* Capture FMTP for Audio/Video */
					if (pt == pss->pt_audio) {
						if (strlen(line) - 7 > 0) {
							const char *fmtp_val = strchr(line, ' '); /* Skip a=fmtp:<pt> */
							if (fmtp_val) {
								while (*fmtp_val == ' ') fmtp_val++;
								lws_strncpy(pss->fmtp_audio, fmtp_val, sizeof(pss->fmtp_audio));
							}
						}
					} else if (pt == pss->pt_video_av1 || pt == pss->pt_video_h264) {
						if (strlen(line) - 7 > 0) {
							const char *fmtp_val = strchr(line, ' ');
							if (fmtp_val) {
								while (*fmtp_val == ' ') fmtp_val++;
								lws_strncpy(pss->fmtp_video, fmtp_val, sizeof(pss->fmtp_video));
							}
						}
					}
				}
			}
		}

		if (!eol) break;
		p_scan = eol + 1;
	}

	lwsl_notice("%s: Extracted MIDs: Audio='%s', Video='%s'\n", __func__, mid_audio, mid_video);

	/* Defaults */
	if (pss->pt_audio == 0) pss->pt_audio = 111;
	if (pss->pt_video_h264 == 0) pss->pt_video_h264 = 0; /* No H264 found */

	/* Preference: H264 > AV1 */
	pss->pt_video = pss->pt_video_h264 ? pss->pt_video_h264 : pss->pt_video_av1;
	if (pss->pt_video == 0) pss->pt_video = 126; /* Fallback? */

	lwsl_notice("%s: Negotiated PTs: Audio=%u, Video=%u (H264=%u, AV1=%u)\n",
			__func__, pss->pt_audio, pss->pt_video, pss->pt_video_h264, pss->pt_video_av1);

	free(sdp_clean);

	/* Sync RTP contexts */
	lws_rtp_init(&pss->rtp_ctx_video, pss->ssrc_video, pss->pt_video);
	lws_rtp_init(&pss->rtp_ctx_audio, pss->ssrc_audio, pss->pt_audio);

	/* Reset DTLS if needed */
	if (pss->handshake_started) {
		lwsl_notice("%s: Existing handshake detected on Offer. Resetting DTLS state.\n", __func__);
		lws_gendtls_destroy(&pss->dtls_ctx);
		pss->handshake_started = 0;
		pss->handshake_done = 0;
	}

	if (!pss->handshake_started) {
		struct lws_gendtls_creation_info ci;
		memset(&ci, 0, sizeof(ci));
		ci.context = vhd->context;
		ci.mode = LWS_GENDTLS_MODE_SERVER;
		ci.mtu = 1100;
		ci.use_srtp = "SRTP_AES128_CM_SHA1_80";
		if (lws_gendtls_create(&pss->dtls_ctx, &ci)) return -1;
		lws_gendtls_set_cert_mem(&pss->dtls_ctx, vhd->cert_mem, vhd->cert_len);
		lws_gendtls_set_key_mem(&pss->dtls_ctx, vhd->key_mem, vhd->key_len);
		pss->handshake_started = 1;
		pss->wsi_udp = vhd->wsi_udp;
	}

	/* Generate Answer */
	char audio_m[2048], video_m[2048], candidates[1024] = "";
	int c_idx = 1;
	size_t n_sdp;

#if defined(LWS_WITH_NETLINK)
	lws_start_foreach_dll(struct lws_dll2 *, d,
			lws_dll2_get_head(lws_routing_table_get(vhd->context))) {
		lws_route_t *rou = lws_container_of(d, lws_route_t, list);
		char ads[64];

		if (rou->src.sa4.sin_family == AF_INET && rou->source_ads) {
			lws_sa46_write_numeric_address(&rou->src, ads, sizeof(ads));
			if (strcmp(ads, "127.0.0.1") && !strstr(candidates, ads)) {
				lws_snprintf(candidates + strlen(candidates),
						sizeof(candidates) - strlen(candidates),
						"a=candidate:%d 1 UDP %u %s %u typ host\\r\\n",
						c_idx++, 2130706431u, ads, vhd->udp_port);
			}
		}
	} lws_end_foreach_dll(d);
#endif

	if (vhd->external_ip[0] && !strstr(candidates, vhd->external_ip)) {
		lws_snprintf(candidates + strlen(candidates),
				sizeof(candidates) - strlen(candidates),
				"a=candidate:%d 1 UDP %u %s %u typ host\\r\\n",
				c_idx++, 2130706431u, vhd->external_ip, vhd->udp_port);
	} else if (!vhd->external_ip[0]) {
		/* If no external IP is configured, we must provide at least our local interface IP */
		char local_ip[46];
		struct sockaddr_storage ss;
		socklen_t slen = sizeof(ss);
		lws_strncpy(local_ip, "127.0.0.1", sizeof(local_ip));
		if (pss->wsi_ws && !getsockname((int)lws_get_socket_fd(pss->wsi_ws), (struct sockaddr *)&ss, &slen)) {
			if (ss.ss_family == AF_INET)
				inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, local_ip, sizeof(local_ip));
			else if (ss.ss_family == AF_INET6)
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, local_ip, sizeof(local_ip));
		}
		if (!strstr(candidates, local_ip)) {
			lws_snprintf(candidates + strlen(candidates),
					sizeof(candidates) - strlen(candidates),
					"a=candidate:%d 1 UDP %u %s %u typ host\\r\\n",
					c_idx++, 2130706431u, local_ip, vhd->udp_port);
		}
	}

	char pt_list[64] = "";
	char rtpmap_lines[512] = "";

	if (pss->pt_video_h264) {
		char b[16], c[256];
		lws_snprintf(b, sizeof(b), "%u ", pss->pt_video_h264);
		strncat(pt_list, b, sizeof(pt_list) - strlen(pt_list) - 1);

		lws_snprintf(c, sizeof(c), "a=rtpmap:%u H264/90000\\r\\n", pss->pt_video_h264);
		strncat(rtpmap_lines, c, sizeof(rtpmap_lines) - strlen(rtpmap_lines) - 1);

		if (pss->fmtp_video[0])
			lws_snprintf(c, sizeof(c), "a=fmtp:%u %s\\r\\n", pss->pt_video_h264, pss->fmtp_video);
		else
			lws_snprintf(c, sizeof(c), "a=fmtp:%u level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42c01f\\r\\n", pss->pt_video_h264);
		strncat(rtpmap_lines, c, sizeof(rtpmap_lines) - strlen(rtpmap_lines) - 1);

		lws_snprintf(c, sizeof(c), "a=rtcp-fb:%u nack\\r\\na=rtcp-fb:%u nack pli\\r\\n", pss->pt_video_h264, pss->pt_video_h264);
		strncat(rtpmap_lines, c, sizeof(rtpmap_lines) - strlen(rtpmap_lines) - 1);
	}

	if (pss->pt_video_av1) {
		char b[16], c[256];
		lws_snprintf(b, sizeof(b), "%u ", pss->pt_video_av1);
		strncat(pt_list, b, sizeof(pt_list) - strlen(pt_list) - 1);

		lws_snprintf(c, sizeof(c), "a=rtpmap:%u AV1/90000\\r\\n", pss->pt_video_av1);
		strncat(rtpmap_lines, c, sizeof(rtpmap_lines) - strlen(rtpmap_lines) - 1);

		lws_snprintf(c, sizeof(c), "a=fmtp:%u profile=0;level-idx=5;tier=0\\r\\n", pss->pt_video_av1);
		strncat(rtpmap_lines, c, sizeof(rtpmap_lines) - strlen(rtpmap_lines) - 1);

		lws_snprintf(c, sizeof(c), "a=rtcp-fb:%u nack\\r\\na=rtcp-fb:%u nack pli\\r\\n", pss->pt_video_av1, pss->pt_video_av1);
		strncat(rtpmap_lines, c, sizeof(rtpmap_lines) - strlen(rtpmap_lines) - 1);
	}

	if (pt_list[0] && pt_list[strlen(pt_list) - 1] == ' ')
		pt_list[strlen(pt_list) - 1] = '\0';

	lws_snprintf(video_m, sizeof(video_m),
			"m=video %u UDP/TLS/RTP/SAVPF %s\\r\\n"
			"c=IN IP4 %s\\r\\n"
			"a=rtcp-mux\\r\\n"
			"a=ice-ufrag:%s\\r\\n"
			"a=ice-pwd:%s\\r\\n"
			"a=fingerprint:sha-256 %s\\r\\n"
			"a=setup:passive\\r\\n"
			"a=mid:%s\\r\\n"
			"a=sendrecv\\r\\n"
			"a=msid:lws-stream lws-track-video\\r\\n"
			"%s"
			"a=rtcp-fb:* goog-remb\\r\\n"
			"a=rtcp-fb:* transport-cc\\r\\n"
			"a=ssrc:%u cname:lws-video\\r\\n"
			"a=ssrc:%u msid:lws-stream lws-track-video\\r\\n"
			"%s"
			"%s"
			"a=end-of-candidates\\r\\n",
		vhd->udp_port, pt_list[0] ? pt_list : "0", vhd->external_ip[0] ? vhd->external_ip : "127.0.0.1",
		pss->ice_ufrag, pss->ice_pwd, vhd->fingerprint,
		mid_video, 
		rtpmap_lines,
		pss->ssrc_video, pss->ssrc_video, candidates, candidates);

	/* Prepare Audio FMTP */
	char fmtp_audio[256] = "";
	if (pss->fmtp_audio[0]) {
		lws_snprintf(fmtp_audio, sizeof(fmtp_audio), "a=fmtp:%u %s;stereo=1;sprop-stereo=1;useinbandfec=1;maxplaybackrate=48000\\r\\n", pss->pt_audio, pss->fmtp_audio);
	} else {
		lws_snprintf(fmtp_audio, sizeof(fmtp_audio), "a=fmtp:%u maxplaybackrate=48000;sprop-stereo=1;stereo=1;useinbandfec=1;maxaveragebitrate=24000\\r\\n", pss->pt_audio);
	}

	lws_snprintf(audio_m, sizeof(audio_m),
			"m=audio %u UDP/TLS/RTP/SAVPF %u\\r\\n"
			"c=IN IP4 %s\\r\\n"
			"a=rtcp-mux\\r\\n"
			"a=ice-ufrag:%s\\r\\n"
			"a=ice-pwd:%s\\r\\n"
			"a=fingerprint:sha-256 %s\\r\\n"
			"a=setup:passive\\r\\n"
			"a=mid:%s\\r\\n"
			"a=sendrecv\\r\\n"
			"a=msid:lws-stream lws-track-audio\\r\\n"
			"a=rtpmap:%u opus/48000/2\\r\\n"
			"%s"
			"a=ssrc:%u cname:lws-audio\\r\\n"
			"a=ssrc:%u msid:lws-stream lws-track-audio\\r\\n"
			"%s"
			"%s"
			"a=end-of-candidates\\r\\n",
			vhd->udp_port, pss->pt_audio, vhd->external_ip[0] ? vhd->external_ip : "127.0.0.1", pss->ice_ufrag, pss->ice_pwd, vhd->fingerprint,
			mid_audio, pss->pt_audio,
			fmtp_audio,
			pss->ssrc_audio, pss->ssrc_audio, candidates, candidates);

	lwsl_notice("%s: Generated Audio FMTP for PT %u\n", __func__, pss->pt_audio);
	char local_ip[46];
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	lws_strncpy(local_ip, vhd->external_ip[0] ? vhd->external_ip : "127.0.0.1", sizeof(local_ip));

	if (wsi && !getsockname((int)lws_get_socket_fd(wsi), (struct sockaddr *)&ss, &slen)) {
		if (ss.ss_family == AF_INET)
			inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, local_ip, sizeof(local_ip));
		else if (ss.ss_family == AF_INET6)
			inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, local_ip, sizeof(local_ip));
	}

	char *json_out = malloc(LWS_PRE + 8192);
	if (!json_out) return -1;
	char *p = json_out + LWS_PRE;

	n_sdp = (size_t)lws_snprintf(p, 8192,
			"{\"type\":\"answer\",\"sdp\":\"v=0\\r\\no=- 123456 2 IN IP4 %s\\r\\ns=-\\r\\nt=0 0\\r\\na=msid-semantic: WMS lws-stream\\r\\na=ice-lite\\r\\na=group:BUNDLE %s %s\\r\\n%s%s\"}",
			local_ip,
			audio_first ? mid_audio : mid_video, audio_first ? mid_video : mid_audio,
			audio_first ? audio_m : video_m, audio_first ? video_m : audio_m);

	write(2, "\n--- START SDP ANSWER ---\n", 26);
	write(2, p, n_sdp);
	write(2, "\n--- END SDP ANSWER ---\n\n", 25);

	if (lws_buflist_append_segment(&pss->buflist, (const uint8_t *)p, n_sdp) < 0) {
		free(json_out);
		return -1;
	}
	lws_callback_on_writable(pss->wsi_ws);
	free(json_out);

	return 0;
}


int
lws_shared_webrtc_callback(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len, struct vhd_webrtc *vhd)
{
	const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
	struct pss_webrtc *pss = (struct pss_webrtc *)user;
	size_t alen;
	const char *val;

	//if (reason == LWS_CALLBACK_SERVER_WRITEABLE)
	//	lwsl_notice("%s: ENTERING (reason %d) vhd=%p, pss=%p\n", __func__, reason, vhd, pss);

	if (!vhd && reason != LWS_CALLBACK_PROTOCOL_INIT && reason != LWS_CALLBACK_PROTOCOL_DESTROY)
		return 0;
	if (!pss && reason != LWS_CALLBACK_PROTOCOL_INIT && reason != LWS_CALLBACK_PROTOCOL_DESTROY)
		return 0;

	switch (reason) {
		case LWS_CALLBACK_PROTOCOL_INIT:
			/* VHD is managed by the application extension now */

			if (!vhd->context) vhd->context = lws_get_context(wsi);
			if (!vhd->vhost) vhd->vhost = lws_get_vhost(wsi);
			if (!vhd->udp_port) vhd->udp_port = 7682;

			if (!pvo) {
				lwsl_vhost_warn(vhd->vhost, "lws-webrtc: No PVOs provided");
				return -1;
			}

			while (pvo) {
				lwsl_notice("%s: Received PVO '%s' = '%s'\n", __func__, pvo->name, pvo->value ? pvo->value : "(null)");
				if (!strcmp(pvo->name, "external-ip"))
					lws_strncpy(vhd->external_ip, pvo->value, sizeof(vhd->external_ip));
				if (!strcmp(pvo->name, "udp-port"))
					vhd->udp_port = (uint16_t)atoi(pvo->value);
				if (!strcmp(pvo->name, "lws-webrtc-ops")) {
					struct lws_webrtc_ops *ops = (struct lws_webrtc_ops *)(uintptr_t)pvo->value;
					if (ops) {
						ops->abi_version        = LWS_WEBRTC_OPS_ABI_VERSION;
						ops->send_video         = lws_webrtc_send_video;
						ops->send_audio         = lws_webrtc_send_audio;
						ops->send_text          = lws_webrtc_send_text;
						ops->send_pli           = lws_webrtc_send_pli;
						ops->foreach_session    = lws_webrtc_foreach_session;
						ops->shared_callback    = lws_shared_webrtc_callback;
						ops->get_user_data      = lws_webrtc_get_user_data;
						ops->set_user_data      = lws_webrtc_set_user_data;
						ops->get_context        = lws_webrtc_get_context;
						ops->get_vhost          = lws_webrtc_get_vhost;
						ops->set_on_media       = lws_webrtc_set_on_media;
						ops->get_video_pt       = lws_webrtc_get_video_pt;
						ops->get_audio_pt       = lws_webrtc_get_audio_pt;
						ops->get_video_pt_h264  = lws_webrtc_get_video_pt_h264;
						ops->get_video_pt_av1   = lws_webrtc_get_video_pt_av1;
						ops->get_seq_video      = lws_webrtc_get_seq_video;
						ops->create_offer       = lws_webrtc_create_offer;
						lwsl_notice("%s: Populated lws-webrtc-ops (ABI %d)\n", __func__, LWS_WEBRTC_OPS_ABI_VERSION);
					}
				}
				pvo = pvo->next;
			}

			/* Generate Identity */
			if (vhd->cert_mem) {
				lwsl_notice("%s: Identity already exists\n", __func__);
				break;
			}

			lwsl_notice("%s: Generating self-signed certificate (this may take a few seconds)...\n", __func__);
			lws_usec_t t1 = lws_now_usecs();
			if (lws_x509_create_self_signed(vhd->context, &vhd->cert_mem, &vhd->cert_len,
						&vhd->key_mem, &vhd->key_len,
						vhd->external_ip, 2048)) {
				lwsl_err("%s: Cert generation failed\n", __func__);
				return -1;
			}
			lwsl_notice("%s: Cert generation took %lldms\n", __func__, (long long)(lws_now_usecs() - t1) / 1000);

			{
				uint8_t hash[32];
				struct lws_genhash_ctx hash_ctx;
				if (!lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256) &&
						!lws_genhash_update(&hash_ctx, vhd->cert_mem, vhd->cert_len) &&
						!lws_genhash_destroy(&hash_ctx, hash)) {
					for (int i = 0; i < 32; i++)
						lws_snprintf(vhd->fingerprint + (i * 3), 4, "%02X%c", hash[i], i == 31 ? '\0' : ':');
				}
			}

			vhd->wsi_udp = lws_create_adopt_udp(vhd->vhost, NULL, vhd->udp_port, LWS_CAUDP_BIND,
					"lws-webrtc-udp", NULL, NULL, NULL, NULL, NULL);
			if (!vhd->wsi_udp) {
				lwsl_err("%s: UDP socket creation failed\n", __func__);
				return -1;
			}
			lwsl_notice("%s: lws-webrtc initialized with external-ip '%s' and udp_port %u\n", __func__, vhd->external_ip, vhd->udp_port);
			lwsl_notice("%s: Certificate Fingerprint: %s\n", __func__, vhd->fingerprint);
			return 0;

		case LWS_CALLBACK_CLIENT_ESTABLISHED:
		case LWS_CALLBACK_ESTABLISHED:
			pss->wsi_ws = wsi;
			pss->wsi_udp = vhd->wsi_udp; /* Critical: Session needs UDP handle */
			if (reason == LWS_CALLBACK_CLIENT_ESTABLISHED)
				pss->is_client = 1;
			lws_dll2_clear(&pss->list);
			lws_dll2_add_tail(&pss->list, &vhd->sessions);
			pss->ssrc_video = (uint32_t)lws_now_usecs();
			pss->ssrc_audio = pss->ssrc_video ^ 0xFFFFFFFF;
			pss->last_tu_id = -1;
			pss->pt_audio = 111;
			pss->sent_first_audio = 0;

			{
				uint8_t rand[16];
				char *pp = pss->ice_pwd;
				int n;

				lws_get_random(vhd->context, rand, 4);
				lws_snprintf(pss->ice_ufrag, sizeof(pss->ice_ufrag),
						"%02X%02X%02X%02X", rand[0], rand[1], rand[2], rand[3]);

				lws_get_random(vhd->context, rand, 16);
				for (n = 0; n < 16; n++)
					pp += lws_snprintf(pp, (size_t)(pss->ice_pwd + sizeof(pss->ice_pwd) - pp),
							"%02X", rand[n]);
			}
			return 0;

		case LWS_CALLBACK_CLIENT_RECEIVE:
		case LWS_CALLBACK_RECEIVE:
			lwsl_debug("%s: LWS_CALLBACK_RECEIVE: len %d\n", __func__, (int)len);
			if (len > 0) {
				char dump[64];
				size_t l = len > 63 ? 63 : len;
				memcpy(dump, in, l);
				dump[l] = '\0';
				lwsl_debug("%s: payload: %s\n", __func__, dump);
			}
			//lwsl_user("LWS_CALLBACK_RECEIVE: %.*s\n", (int)len, (const char *)in);
			if (lws_json_simple_find((const char *)in, len, "\"type\":", &alen))
				val = lws_json_simple_find((const char *)in, len, "\"type\":", &alen);
			else
				val = NULL;

			// if (val) lwsl_notice("lws_json_simple_find returned: '%.*s' (len %d)\n", (int)alen, val, (int)alen);
			// else lwsl_notice("lws_json_simple_find returned NULL\n");

			if ((val && alen >= 7 && !strncmp(val, "\"offer\"", 7)) ||
					(val && alen >= 5 && !strncmp(val, "offer", 5))) {
				handle_offer(wsi, pss, vhd, (const char *)in, len);
			} else if ((val && alen >= 8 && !strncmp(val, "\"answer\"", 8)) ||
					(val && alen >= 6 && !strncmp(val, "answer", 6))) {
				handle_answer(wsi, pss, vhd, (const char *)in, len);
			}
			break;

		case LWS_CALLBACK_HTTP_FILE_COMPLETION:
			// return -1; /* falling through to close transaction inside dummy cb leads to delays */
			break;

		case LWS_CALLBACK_CLIENT_WRITEABLE:
		case LWS_CALLBACK_SERVER_WRITEABLE:
			{
				uint8_t *buf;
				size_t xlen;


				// lwsl_err("%s: WRITEABLE callback! Draining buffer...\n", __func__);
				// lwsl_notice("%s: WRITEABLE callback! Checking buflist %p\n", __func__, &pss->buflist);

				while ((xlen = lws_buflist_next_segment_len(&pss->buflist, &buf))) {
					// lwsl_notice("%s: Found segment len %zu\n", __func__, xlen);
					uint8_t *p = malloc(LWS_PRE + xlen);
					int m;

					if (!p) {
						lwsl_err("%s: OOM in WRITEABLE (len %zu)\n", __func__, xlen);
						return -1;
					}
					memcpy(p + LWS_PRE, buf, xlen);

					m = lws_write(wsi, p + LWS_PRE, xlen, LWS_WRITE_TEXT);
					// lwsl_notice("%s: lws_write returned %d\n", __func__, m);
					if (m < 0) {
						lwsl_err("%s: lws_write failed with %d (len %zu). Closing.\n", __func__, m, xlen);
						free(p);
						return -1; // Close connection
					}

					/*
					 * Actually, if lws_write returns < xlen, it usually means backpressure
					 * and it has buffered what it could.
					 *
					 * If we unconditionally consume the segment from buflist, we assume LWS took it all
					 * (even if buffered internally).
					 */

					lws_buflist_use_segment(&pss->buflist, xlen);
					free(p); /* We can free p because lws_write copies or buffers */

					if (lws_buflist_next_segment_len(&pss->buflist, NULL)) {
						lws_callback_on_writable(wsi);
					}
				}
				// if (count) lwsl_notice("%s: Sent %d buffered messages\n", __func__, count);
				break;
			}

		case LWS_CALLBACK_CLOSED:
			lwsl_notice("%s: LWS_CALLBACK_CLOSED\n", __func__);
			if (!lws_dll2_is_detached(&pss->list))
				lws_dll2_remove(&pss->list);
			if (pss->handshake_started) {
				lws_gendtls_destroy(&pss->dtls_ctx);
				pss->handshake_started = 0;
			}
			lws_buflist_destroy_all_segments(&pss->buflist);
			break;

		case LWS_CALLBACK_PROTOCOL_DESTROY:
			if (vhd) {
				free(vhd->cert_mem); free(vhd->key_mem);
			}
			break;

		default:
			break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* Helper: Find session by peer address */
	static struct pss_webrtc *
webrtc_find_session(struct vhd_webrtc *vhd, const struct sockaddr_in *sin)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->sessions.head) {
		struct pss_webrtc *s = lws_container_of(d, struct pss_webrtc, list);
		if (s->has_peer_sin &&
				s->peer_sin.sin_addr.s_addr == sin->sin_addr.s_addr &&
				s->peer_sin.sin_port == sin->sin_port) {
			return s;
		}
	} lws_end_foreach_dll(d);
	return NULL;
}

/* Helper: Handle STUN packets */
	static int
webrtc_handle_stun(struct lws *wsi, struct vhd_webrtc *vhd, struct pss_webrtc **ppss,
		const struct sockaddr_in *sin, uint8_t *in, size_t len)
{
	struct pss_webrtc *pss = *ppss;
	uint8_t *p = (uint8_t *)in;
	uint16_t type = (uint16_t)((p[0] << 8) | p[1]);
	char ads[64];

	lws_sa46_write_numeric_address((lws_sockaddr46 *)sin, ads, sizeof(ads));

	if (type == 0x0101) { /* Binding Success Response */
		lwsl_notice("%s: Received STUN Binding Success Response from %s:%u\n", __func__, "peer", ntohs(sin->sin_port));
		return 0;
	}

	if (type != LWS_STUNREQ_BINDING)
		return 0;

	/* If we don't know the PSS yet (NAT), try to find it via USERNAME */
	if (!pss) {
		/* Parse attributes to find USERNAME */
		size_t i = 20;
		while (i + 4 <= len) {
			uint16_t attr_type = (uint16_t)((p[i] << 8) | p[i + 1]);
			uint16_t attr_len = (uint16_t)((p[i + 2] << 8) | p[i + 3]);

			if (attr_type == LWS_STUN_ATTR_USERNAME) { /* USERNAME */
				if (i + 4 + attr_len > len)
					break;

				char username[128];
				if (attr_len >= sizeof(username))
					break;

				memcpy(username, p + i + 4, attr_len);
				username[attr_len] = '\0';

				/* Format is DestUfrag:SrcUfrag */
				char *colon = strchr(username, ':');
				if (colon) {
					*colon = '\0';
					const char *u_dest = username; // Server Ufrag (Ours)
					const char *u_src = colon + 1; // Client Ufrag (Theirs)

					lws_start_foreach_dll(struct lws_dll2 *, d, vhd->sessions.head) {
						struct pss_webrtc *s = lws_container_of(d, struct pss_webrtc, list);
						// Match first part against our ufrag
						if (!strcmp(s->ice_ufrag, u_dest)) {
							lwsl_notice("%s: Found PSS %p via STUN Username '%s:%s' (Peer IP update)\n",
									__func__, s, u_dest, u_src);
							pss = s;
							pss->peer_sin = *sin;
							pss->has_peer_sin = 1;
							*ppss = s;
							break;
						}
					} lws_end_foreach_dll(d);
				}
				break; /* Found USERNAME or malformed */
			}
			i += 4 + attr_len;
			i = (i + 3) & ~3u; /* Align to 4 bytes */
		}
	}

	// lwsl_notice("%s: Incoming STUN Request from %s:%u session %p\n", __func__, ads, ntohs(sin->sin_port), pss);
	uint8_t out[512];
	int n_stun = lws_stun_validate_and_reply(wsi, (uint8_t *)in, len, out, sizeof(out), pss ? pss->ice_pwd : NULL, sin);
	if (n_stun > 0) {
		// lwsl_notice("%s: Sending STUN reply (%d bytes)\n", __func__, n_stun);
		sendto(lws_get_socket_fd(wsi), (const char *)out, (size_t)n_stun, 0, (const struct sockaddr *)sin, sizeof(*sin));
	} else {
		lwsl_err("%s: lws_stun_validate_and_reply failed (pss %p)\n", __func__, pss);
	}

	return 0;
}

/* Helper: Handle DTLS packets */
	static int
webrtc_handle_dtls(struct lws *wsi, struct pss_webrtc *pss, const struct sockaddr_in *sin,
		uint8_t *in, size_t len)
{
	if (!pss || !pss->handshake_started)
		return 0;

	lwsl_notice("%s: Incoming DTLS/RTP packet (%zu bytes)\n", __func__, len);

	if (lws_gendtls_put_rx(&pss->dtls_ctx, (uint8_t *)in, len) == 0) {
		/* Drive state machine by reading */
		uint8_t rx_dump[2048];
		while (lws_gendtls_get_rx(&pss->dtls_ctx, rx_dump, sizeof(rx_dump)) > 0);
		/* Check if we need to send anything */
		uint8_t out[2048];
		int _tx_len;
		while ((_tx_len = lws_gendtls_get_tx(&pss->dtls_ctx, out, sizeof(out))) > 0) {
			lwsl_notice("%s: Sending DTLS Reply (%d bytes)\n", __func__, _tx_len);
			sendto(lws_get_socket_fd(wsi), (const char *)out, (size_t)_tx_len, 0, (const struct sockaddr *)sin, sizeof(*sin));
		}

		if (!pss->handshake_done && lws_gendtls_handshake_done(&pss->dtls_ctx)) {
			pss->handshake_done = 1;
			lwsl_notice("%s: DTLS Handshake DONE! Cipher: %s\n", __func__, lws_gendtls_get_srtp_profile(&pss->dtls_ctx));

			/* Initialize SRTP */
			uint8_t k[60];
			if (lws_gendtls_export_keying_material(&pss->dtls_ctx, "EXTRACTOR-dtls_srtp", 19, NULL, 0, k, 60) == 0) {
				if (pss->is_client) {
					/* Client Mode: TX using Client Keys (0/32), RX using Server Keys (16/46) */
					lwsl_notice("%s: SRTP Client Mode: TX=Client keys, RX=Server keys\n", __func__);
					lws_srtp_init(&pss->srtp_ctx_tx, LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80, k + 0, k + 32);
					lws_srtp_init(&pss->srtp_ctx_rx, LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80, k + 16, k + 46);
				} else {
					/* Server Mode: TX using Server Keys (16/46), RX using Client Keys (0/32) */
					lwsl_notice("%s: SRTP Server Mode: TX=Server keys, RX=Client keys\n", __func__);
					lws_srtp_init(&pss->srtp_ctx_tx, LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80, k + 16, k + 46);
					lws_srtp_init(&pss->srtp_ctx_rx, LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80, k + 0, k + 32);
				}

				lws_rtp_init(&pss->rtp_ctx_video, pss->ssrc_video, pss->pt_video);
				lws_rtp_init(&pss->rtp_ctx_audio, pss->ssrc_audio, pss->pt_audio);
				lwsl_notice("%s: SRTP/RTP contexts initialized: Video SSRC %u (PT %u), Audio SSRC %u (PT %u)\n",
						__func__, pss->ssrc_video, pss->pt_video, pss->ssrc_audio, pss->pt_audio);
			}
		}
	} else {
		lwsl_err("%s: lws_gendtls_put_rx failed\n", __func__);
	}

	return 0;
}

/* Helper: Handle RTP/RTCP packets */
	static int
webrtc_handle_rtp_rtcp(struct lws *wsi, struct vhd_webrtc *vhd, struct pss_webrtc *pss,
		const struct sockaddr_in *sin, uint8_t *in, size_t len)
{
	(void)wsi; (void)sin;
	uint8_t *p = (uint8_t *)in;

	if (!pss || !pss->handshake_done) return 0;

	uint8_t pt_raw = p[1];

	/*
	 * Check for valid RTCP Payload Types (200-215) per RFC 5761.
	 * This range includes SR(200), RR(201), SDES(202), BYE(203), APP(204),
	 * RTPFB(205), PSFB(206 - e.g. PLI), XR(207), AVB(208), etc.
	 *
	 * Everything else in this range (< 200) is treated as RTP.
	 */
	if (pt_raw >= 200 && pt_raw <= 215) { /* RTCP */
		size_t rtcp_len = len;
		lws_srtp_unprotect_rtcp(&pss->srtp_ctx_rx, (uint8_t *)in, &rtcp_len);
	} else { /* RTP */
		size_t rtp_len = len;
		int ret = lws_srtp_unprotect_rtp(&pss->srtp_ctx_rx, (uint8_t *)in, &rtp_len);
		if (ret == 0 && vhd->on_media) {
			uint32_t ssrc = (uint32_t)((p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11]);
			uint8_t pkt_pt = pt_raw & 0x7f;
#if 0
			/* Log incoming packet types intermittently */
			if ((p[2] << 8 | p[3]) % 100 == 0) {
				lwsl_notice("%s: Inbound RTP pkt_pt=%u (Expected Audio=%u, Video=%u, vH264=%u, vAV1=%u)\n",
						__func__, pkt_pt, pss->pt_audio, pss->pt_video, pss->pt_video_h264, pss->pt_video_av1);
			}
#endif

			/* Check for sequence number gaps on video tracks */
			if (pkt_pt == pss->pt_video || pkt_pt == pss->pt_video_h264 || pkt_pt == pss->pt_video_av1) {
				uint16_t seq = (uint16_t)((p[2] << 8) | p[3]);
				if (pss->seq_valid_video) {
					uint16_t expected = (uint16_t)(pss->last_seq_video + 1);
					if (seq != expected) {
						if (lws_now_usecs() - pss->last_pli_req_time > 200000) {
							lwsl_notice("%s: RTP Drop (Video): Got %u, Expected %u. Requesting PLI.\n", __func__, seq, expected);
							lws_webrtc_send_pli(pss);
							pss->last_pli_req_time = lws_now_usecs();
						}
					}
				}
				pss->last_seq_video = seq;
				pss->seq_valid_video = 1;
			}

			/* Check for sequence number gaps on audio tracks */
			if (pkt_pt == pss->pt_audio) {
				uint16_t seq = (uint16_t)((p[2] << 8) | p[3]);
				if (pss->seq_valid_audio) {
					uint16_t expected = (uint16_t)(pss->last_seq_audio + 1);
					if (seq != expected) {
						lwsl_warn("%s: RTP Drop (Audio): Got %u, Expected %u (Gap %d)\n",
								__func__, seq, expected, seq - expected);
					}
				}
				pss->last_seq_audio = seq;
				pss->seq_valid_audio = 1;
			}

			// Logic from old block for PLI/header culling...
			size_t offset = LWS_RTP_HEADER_LEN;
			uint8_t cc = p[0] & 0x0f;

			if (!pss->ssrc_peer_video && pkt_pt != pss->pt_audio) {
				if (pkt_pt != pss->pt_video)
					lwsl_notice("%s: PT mismatch (Expected Video %u, got %u), but taking SSRC %u anyway\n", __func__, pss->pt_video, pkt_pt, ssrc);
				pss->ssrc_peer_video = ssrc;
				lwsl_notice("%s: Discovered peer Video SSRC %u, triggering PLI\n", __func__, ssrc);
				lws_webrtc_send_pli(pss);
			}

			offset += (cc * 4);
			if (p[0] & 0x10) { /* X bit */
				if (rtp_len >= offset + 4) {
					uint16_t ext_len = (uint16_t)((p[offset + 2] << 8) | p[offset + 3]);
					offset += 4u + (size_t)(ext_len * 4);
				}
			}
			if (p[0] & 0x20) { /* P bit */
				if (rtp_len > offset) {
					uint8_t padding = p[rtp_len - 1];
					if (rtp_len >= offset + padding) rtp_len -= padding;
				}
			}

			if (rtp_len > offset) {
#if 0
				static int dbg_fwd = 0;
				if (dbg_fwd++ % 100 == 0)
					lwsl_notice("%s: Forwarding RTP to on_media: PT %u, len %zu, ssrc %u\n", __func__, pkt_pt, rtp_len - offset, ssrc);
#endif
				vhd->on_media(pss->wsi_ws, pkt_pt, (uint8_t *)in + offset, rtp_len - offset, !!(p[1] & 0x80), (uint32_t)((p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7]));
			}
		}
	}
	return 0;
}

	int
lws_shared_webrtc_udp_callback(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len, struct vhd_webrtc_udp *vhd_u)
{
	/*
	 * For UDP callbacks, we use the passed-in VHD which points back to the
	 * main "lws-webrtc" protocol VHD.
	 */
	struct vhd_webrtc *vhd = vhd_u ? vhd_u->vhd : NULL;
	struct pss_webrtc *pss = NULL;
	const struct lws_udp *udp_desc = lws_get_udp(wsi);


	if (reason == LWS_CALLBACK_RAW_RX)
		lwsl_debug("%s: reason %d, vhd %p, len %d\n", __func__, (int)reason, vhd, (int)len);

	if (!vhd && reason != LWS_CALLBACK_PROTOCOL_INIT && reason != LWS_CALLBACK_PROTOCOL_DESTROY)
		return 0;

	switch (reason) {
		case LWS_CALLBACK_RAW_ADOPT:
			lwsl_notice("%s: RAW_ADOPT, increasing SO_SNDBUF\n", __func__);
			{
				int sndbuf = 8 * 1024 * 1024;
				if (setsockopt(lws_get_socket_fd(wsi), SOL_SOCKET, SO_SNDBUF, (const char *)&sndbuf, sizeof(sndbuf)) < 0) {
					lwsl_err("%s: Failed to scale SO_SNDBUF: %d\n", __func__, errno);
				}
				/* Also increase RCVBUF to handle bursty 300KB frames without drops */
				if (setsockopt(lws_get_socket_fd(wsi), SOL_SOCKET, SO_RCVBUF, (const char *)&sndbuf, sizeof(sndbuf)) < 0) {
					lwsl_err("%s: Failed to scale SO_RCVBUF: %d\n", __func__, errno);
				}
			}
			break;

		case LWS_CALLBACK_RAW_RX:
			if (!vhd || !udp_desc) return 0;
			const struct sockaddr_in *sin = &udp_desc->sa46.sa4;
			// char ads[64];
			// lws_sa46_write_numeric_address((lws_sockaddr46 *)sin, ads, sizeof(ads));
			// lwsl_notice("%s: RAW_RX %zu bytes from %s:%u\n", __func__, len, ads, ntohs(sin->sin_port));

			/* Find session by address */
			pss = webrtc_find_session(vhd, sin);

			if (len > 0) {
				uint8_t *p = (uint8_t *)in;
				uint8_t b0 = p[0];

				/* STUN: 0x00 or 0x01 */
				if (b0 == 0 || b0 == 1) {
					webrtc_handle_stun(wsi, vhd, &pss, sin, (uint8_t *)in, len);
				}
				/* DTLS: 20-63 */
				else if (b0 >= 20 && b0 <= 63) {
					webrtc_handle_dtls(wsi, pss, sin, (uint8_t *)in, len);
				}
				/* RTP/RTCP: 128-191 */
				else if (b0 >= 128 && b0 <= 191) {
					webrtc_handle_rtp_rtcp(wsi, vhd, pss, sin, (uint8_t *)in, len);
				}
			}
			break;
		default: break;
	}
	return 0;
}


	int
callback_webrtc_udp(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct vhd_webrtc_udp *vhd = (struct vhd_webrtc_udp *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));

	if (reason == LWS_CALLBACK_PROTOCOL_INIT) {
		const struct lws_protocols *p;

		// lwsl_vhost_notice(lws_get_vhost(wsi), "plugin 'lws-webrtc-udp' PROTOCOL_INIT\n");

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi), sizeof(struct vhd_webrtc_udp));
		if (!vhd)
			return -1;

		p = lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-webrtc");
		if (p)
			vhd->vhd = (struct vhd_webrtc *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), p);

		if (!vhd->vhd) {
			lwsl_vhost_warn(lws_get_vhost(wsi), "lws-webrtc: main 'lws-webrtc' vhd not found");
			/* This might happen if init order is wrong or not on same vhost */
			return -1;
		}
	}

	return lws_shared_webrtc_udp_callback(wsi, reason, user, in, len, vhd);
}


	int
callback_webrtc(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct vhd_webrtc *vhd = (struct vhd_webrtc *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));

	if (reason == LWS_CALLBACK_PROTOCOL_INIT) {

		if (!in)
			return -1;

		lwsl_vhost_notice(lws_get_vhost(wsi), "plugin 'lws-webrtc' PROTOCOL_INIT\n");

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi), sizeof(struct vhd_webrtc));
		if (!vhd)
			return -1;
	}

	return lws_shared_webrtc_callback(wsi, reason, user, in, len, vhd);
}

static const struct lws_webrtc_ops webrtc_ops = {
	.abi_version		= LWS_WEBRTC_OPS_ABI_VERSION,
	.send_video		= lws_webrtc_send_video,
	.send_audio		= lws_webrtc_send_audio,
	.send_text		= lws_webrtc_send_text,
	.foreach_session	= lws_webrtc_foreach_session,
	.shared_callback	= lws_shared_webrtc_callback,
	.get_user_data		= lws_webrtc_get_user_data,
	.set_user_data		= lws_webrtc_set_user_data,
	.get_vhost		= lws_webrtc_get_vhost,
	.get_context		= lws_webrtc_get_context,
	.set_on_media		= lws_webrtc_set_on_media,
	.send_pli		= lws_webrtc_send_pli,
	.get_video_pt		= lws_webrtc_get_video_pt,
	.get_audio_pt		= lws_webrtc_get_audio_pt,
	.get_video_pt_h264	= lws_webrtc_get_video_pt_h264,
	.get_video_pt_av1	= lws_webrtc_get_video_pt_av1,
	.get_seq_video      = lws_webrtc_get_seq_video,
};

LWS_VISIBLE const struct lws_protocols webrtc_protocols[] = {
	{ "lws-webrtc", callback_webrtc, sizeof(struct pss_webrtc), 4096, 0, (void *)&webrtc_ops, 0 },
	{ "lws-webrtc-udp", callback_webrtc_udp, 0, 2048, 0, NULL, 0 },
};

#if !defined (LWS_WITH_PLUGINS_BUILTIN)
LWS_VISIBLE const lws_plugin_protocol_t lws_webrtc = {
	.hdr = {
		"lws webrtc",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC,
		100, /* priority */
	},
	.protocols = webrtc_protocols,
	.count_protocols = LWS_ARRAY_SIZE(webrtc_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
#endif
