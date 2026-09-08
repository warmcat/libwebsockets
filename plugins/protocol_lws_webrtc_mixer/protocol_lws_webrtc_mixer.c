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

#include <libwebsockets.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../protocol_lws_webrtc/protocol_lws_webrtc.h"
#include "mixer-media.h"
#include <libwebsockets/lws-rtp.h>

const struct lws_webrtc_ops *we_ops;

/*
 * Room names come from an unauthenticated peer's URI, become the room's
 * identity and appear in logs: restrict them to a conservative charset and
 * length rather than accepting whatever arrived.
 */
static int
mixer_room_name_ok(const char *name, size_t len)
{
	size_t n;

	if (!len || len > 31)
		return 0;

	for (n = 0; n < len; n++) {
		char c = name[n];

		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')
			continue;

		return 0;
	}

	return 1;
}

static struct mixer_room *
get_or_create_room(struct vhd_mixer *vhd, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->rooms)) {
		struct mixer_room *r = lws_container_of(d, struct mixer_room, list);
		if (!strcmp(r->name, name))
			return r;
	} lws_end_foreach_dll(d);

	/*
	 * Rooms live until the vhost goes away (the worker thread holds
	 * pointers to them, see the ownership rule in mixer-media.h) and each
	 * one is a full GStreamer encode pipeline, so we cannot let an
	 * unauthenticated peer conjure them up without limit.
	 */
	if (vhd->num_rooms >= vhd->max_rooms) {
		lwsl_warn("%s: refusing room '%s': at the %d room limit\n",
			  __func__, name, vhd->max_rooms);
		return NULL;
	}

	struct mixer_room *r = malloc(sizeof(*r));
	if (!r) return NULL;
	memset(r, 0, sizeof(*r));
	lws_strncpy(r->name, name, sizeof(r->name));
	r->vhd = vhd;

	/* Default audio limits */
	r->audio_info.squelch_level = 1000.0;
	r->audio_info.max_energy = 327680.0;
	r->audio_info.sample_stride = 48;

	r->master_w = LWS_RTP_VIDEO_WIDTH_720P;
	r->master_h = LWS_RTP_VIDEO_HEIGHT_720P;

	/* Initialize Performance Tracker (2 levels: 0=High Quality, 1=Fallback) */
	/* 5s short-term EWMA for quick drops, 60s long-term EWMA for sustained recovery */
	r->adapt_h264 = lws_adapt_create(2, 5 * LWS_US_PER_SEC, 60 * LWS_US_PER_SEC);

	if (mixer_room_init(r) < 0) {
		lws_adapt_destroy(&r->adapt_h264);
		free(r);
		return NULL;
	}

	lws_dll2_add_tail(&r->list, &vhd->rooms);
	vhd->num_rooms++;

	lwsl_notice("%s: Created room '%s'\n", __func__, name);
	return r;
}

struct broadcast_ctx {
	struct mixer_room *room;
	const char *text;
	size_t len;
	int require_joined;
	struct participant *exclude;
};

static int broadcast_text_iter(struct lws_dll2 *d, void *user);
static void broadcast_client_list(struct mixer_room *r, struct participant *exclude);
static void broadcast_layout(struct mixer_room *r);
static void mixer_send_text(struct participant *p, const char *buf, size_t len);

static void
sul_stats_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_mixer *vhd = lws_container_of(sul, struct vhd_mixer, sul_stats);

	static int tick = 0;
	tick++;

	/* Rate: 4Hz (every 250ms) */

	/* 1. VU Meter (Audio Energy) every tick */
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->rooms)) {
		struct mixer_room *r = lws_container_of(d, struct mixer_room, list);
		lws_start_foreach_dll(struct lws_dll2 *, d1, lws_dll2_get_head(&r->participants)) {
			struct participant *p = lws_container_of(d1, struct participant, list);
			if (p->pss && p->session) {
				char json[64];
				/* Copy latest energy from worker session */
				p->audio_energy = p->session->audio_energy;
				lws_snprintf(json, sizeof(json), "{\"type\":\"audio_level\",\"level\":%d}", p->audio_energy);
				mixer_send_text(p, json, strlen(json));
			}
		} lws_end_foreach_dll(d1);
	} lws_end_foreach_dll(d);

	/* 2. System Status and FPS (every 4th tick = 1s) */
	if (tick % 4 == 0) {
		char json[256], buf[16];
		int temp = 0, fd, len;
		double load[3];

		/* Read temperature */
		fd = open("/sys/class/thermal/thermal_zone0/temp", O_RDONLY);
		if (fd < 0) fd = open("/sys/class/thermal/thermal_zone1/temp", O_RDONLY);
		if (fd >= 0) {
			int n = (int)read(fd, buf, sizeof(buf) - 1);
			if (n > 0) { buf[n] = '\0'; temp = atoi(buf); }
			close(fd);
		}

		/* Read load average */
		if (getloadavg(load, 3) != 3) { load[0] = 0; load[1] = 0; load[2] = 0; }

		len = lws_snprintf(json, sizeof(json),
				"{\"type\":\"sys_status\",\"temp\":%d,\"load\":[%.2f,%.2f,%.2f]}",
				temp, load[0], load[1], load[2]);

		struct broadcast_ctx bctx = { .text = json, .len = (size_t)len, .exclude = NULL };

		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->rooms)) {
			struct mixer_room *r = lws_container_of(d, struct mixer_room, list);

			/* Update Participant Stats (FPS) */
			lws_start_foreach_dll(struct lws_dll2 *, d1, lws_dll2_get_head(&r->participants)) {
				struct participant *p = lws_container_of(d1, struct participant, list);
				if (p->session) {
					lws_usec_t now = lws_now_usecs();
					if (now - p->session->last_fps_check > 1000000) {
						uint32_t diff = p->session->processed_frames_count - p->session->last_processed_frames_count;
						lws_usec_t interval_us = now - p->session->last_fps_check;

						/* Cast to uint64_t to prevent overflow when diff * 1000000 exceeds 32-bit limits */
						p->session->current_fps = (int)(((uint64_t)diff * 1000000ULL) / (unsigned long long)interval_us);

						/* Temporary logging to prove FPS calc and catch negative values */
						if (p->session->current_fps < 0 || p->session->current_fps > 100) {
							lwsl_notice("DIAGNOSTIC FPS BUG: diff=%u, interval=%llu, fps=%d\n", diff, (unsigned long long)interval_us, p->session->current_fps);
						}

						p->session->last_fps_check = now;
						p->session->last_processed_frames_count = p->session->processed_frames_count;

						/* Calculate Telemetry Rates */
						uint32_t rtp_drop_v_sec = 0, rtp_late_v_sec = 0, dtls_err_sec = 0, tx_drop_sec = 0;
						if (p->pss && p->pss->media) {
							rtp_drop_v_sec = p->pss->media->telemetry.rtp_drops_video - p->last_telemetry.rtp_drops_video;
							rtp_late_v_sec = p->pss->media->telemetry.rtp_late_video - p->last_telemetry.rtp_late_video;
							dtls_err_sec = p->pss->media->telemetry.dtls_errors - p->last_telemetry.dtls_errors;
							tx_drop_sec = p->pss->media->telemetry.txpacer_drops - p->last_telemetry.txpacer_drops;
							p->last_telemetry = p->pss->media->telemetry;
						}

						uint32_t qos_drop_sec = p->session->gst_qos_drops - p->last_gst_qos_drops;
						p->last_gst_qos_drops = p->session->gst_qos_drops;

						char tel_str[256];
						lws_snprintf(tel_str, sizeof(tel_str),
							"\nRTP Drp: %u (%u/s) Late: %u (%u/s)\nDTLS Err: %u (%u/s) Tx Drp: %u (%u/s)\nQOS Drp: %u (%u/s)",
							p->pss && p->pss->media ? p->pss->media->telemetry.rtp_drops_video : 0, rtp_drop_v_sec,
							p->pss && p->pss->media ? p->pss->media->telemetry.rtp_late_video : 0, rtp_late_v_sec,
							p->pss && p->pss->media ? p->pss->media->telemetry.dtls_errors : 0, dtls_err_sec,
							p->pss && p->pss->media ? p->pss->media->telemetry.txpacer_drops : 0, tx_drop_sec,
							p->session->gst_qos_drops, qos_drop_sec);

						if (p->client_stats[0]) {
							lws_snprintf(p->stats, sizeof(p->stats), "%s | Rx: %dfps%s",
									p->client_stats, p->session->current_fps, tel_str);
						} else {
							lws_snprintf(p->stats, sizeof(p->stats), "Rx: %dfps%s",
									p->session->current_fps, tel_str);
						}

						/* keep the worker's snapshot in step */
						mixer_media_session_set_ident(p->session,
								p->name, p->stats);
					}
				}
			} lws_end_foreach_dll(d1);

			/* Broadcast client list mapped with newest FPS */
			broadcast_client_list(r, NULL);
			broadcast_layout(r);

			/* Broadcast sys_status */
			bctx.room = r;
			lws_dll2_foreach_safe(&r->participants, &bctx, broadcast_text_iter);
		} lws_end_foreach_dll(d);
	}

	lws_sul_schedule(we_ops->get_context(vhd->vhd), 0, &vhd->sul_stats, sul_stats_cb, 250 * LWS_US_PER_MS);
}


static int
broadcast_text_iter(struct lws_dll2 *d, void *user)
{
	struct broadcast_ctx *ctx = (struct broadcast_ctx *)user;
	struct participant *p = lws_container_of(d, struct participant, list);

	if (p != ctx->exclude && p->pss) {
		if (ctx->require_joined && !p->joined) return 0;
		mixer_send_text(p, ctx->text, ctx->len);
	}

	return 0;
}

static void
broadcast_client_list(struct mixer_room *r, struct participant *exclude)
{
	struct broadcast_ctx bctx;
	char buf[LWS_PRE + 2048], *p = buf + LWS_PRE, *end = buf + sizeof(buf);

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{\"type\":\"client_list\",\"clients\":[");

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&r->participants)) {
		struct participant *part = lws_container_of(d, struct participant, list);
		if (part != lws_container_of(lws_dll2_get_head(&r->participants), struct participant, list))
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ",");

		char stats_esc[128] = {0};
		char name_esc[192] = {0};
		lws_json_purify(stats_esc, part->stats, sizeof(stats_esc), NULL);
		lws_json_purify(name_esc, part->name, sizeof(name_esc), NULL);

		char id_esc[64] = {0};
		lws_json_purify(id_esc, part->id, sizeof(id_esc), NULL);

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				"{\"id\":\"%s\",\"name\":\"%s\",\"joined\":%s,\"stats\":\"%s\"}",
				id_esc, name_esc, part->joined ? "true" : "false", stats_esc);
	} lws_end_foreach_dll(d);

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "]}");

	bctx.room = r;
	bctx.text = buf + LWS_PRE;
	bctx.len = strlen(bctx.text);
	bctx.require_joined = 0;
	bctx.exclude = exclude;

	lws_dll2_foreach_safe(&r->participants, &bctx, broadcast_text_iter);
}

static void
broadcast_layout(struct mixer_room *r)
{
	struct broadcast_ctx bctx;
	char *json = NULL;

	/*
	 * The layout context belongs to the worker thread; it renders the
	 * JSON there and publishes just the string.  We take a private copy
	 * under the lock so we never hold it across the broadcast.
	 */
	lws_mutex_lock(r->mutex_layout);
	if (r->layout_json)
		json = strdup(r->layout_json);
	lws_mutex_unlock(r->mutex_layout);

	if (!json) return;

	bctx.room = r;
	bctx.text = json;
	bctx.len = strlen(json);
	bctx.require_joined = 0;
	bctx.exclude = NULL;

	lws_dll2_foreach_safe(&r->participants, &bctx, broadcast_text_iter);

	free(json);
}

/*
 * Queue text to one participant.
 *
 * we_ops->send_text() only appends to the pss's buflist and nothing bounds
 * it, so a peer that stops reading its socket but keeps asking us for things
 * would make us allocate without limit on its behalf.  Past a backlog
 * threshold we drop instead of queueing.
 */
static void
mixer_send_text(struct participant *p, const char *buf, size_t len)
{
	if (!p || !p->pss)
		return;

	if (lws_buflist_total_len(&p->pss->buflist) > MIXER_MAX_TX_BACKLOG) {
		lwsl_warn("%s: tx backlog for '%s' over limit, dropping\n",
			  __func__, p->id);
		return;
	}

	we_ops->send_text(p->pss, buf, len);
}

/*
 * Copy a JSON string value that lws_json_simple_find() returned into a
 * bounded destination.
 *
 * lws_json_simple_find() already strips the quotes and hands back the exact
 * length, so there is nothing to fix up afterwards.  The old
 * `if (*v == '"') { v++; nl -= 2; }` idiom fired precisely on an empty value
 * ("", where the returned pointer is the closing quote and alen is 0) and
 * underflowed the length to SIZE_MAX, over-reading past the end of the ws rx
 * buffer.  Returns 0 only if a non-empty value that fits was copied.
 */
static int
mixer_json_str(char *dest, size_t dest_len, const char *v, size_t al)
{
	if (!v || !al || al >= dest_len)
		return -1;

	memcpy(dest, v, al);
	dest[al] = '\0';

	return 0;
}

static struct participant *
find_participant_by_id(struct mixer_room *r, const char *id)
{
	if (!r || !id || !id[0])
		return NULL;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&r->participants)) {
		struct participant *tp = lws_container_of(d, struct participant, list);

		if (!strcmp(tp->id, id))
			return tp;
	} lws_end_foreach_dll(d);

	return NULL;
}

/*
 * Who may drive `tp`'s camera controls or read its device capabilities?
 *
 * Only tp itself, or the room's controller (the first participant to arrive
 * in the room).  Signalling here is unauthenticated and peers used to be
 * addressed by the display name they chose for themselves, so any peer could
 * name any other and take over its camera.  See README.md.
 */
static int
mixer_may_control(struct participant *p, struct participant *tp)
{
	return p == tp || p->controller;
}

/*
 * Send `of`'s cached device-capability blob to `to`.
 *
 * The blob is raw bytes from the owning peer: it is never parsed, so it must
 * not be spliced into the message as JSON.  Doing that let any peer close
 * the enclosing object and append its own top-level keys --- ie, forge
 * arbitrary "server" messages, including a WebRTC answer or ICE candidate,
 * to every other peer in the room.  We escape it and send it as a JSON
 * *string*, which the client parses separately.
 */
static void
send_remote_caps(struct participant *to, struct participant *of,
		 const char *blob)
{
	char esc_id[64], esc_name[384], *esc, *msg;
	size_t esc_len, msg_len;
	int n;

	if (!blob || !to->pss)
		return;

	esc_len = (strlen(blob) * 6) + 1;
	msg_len = esc_len + 512;

	esc = malloc(esc_len);
	if (!esc)
		return;

	msg = malloc(msg_len);
	if (!msg) {
		free(esc);
		return;
	}

	lws_json_purify(esc, blob, (int)esc_len, NULL);
	lws_json_purify(esc_id, of->id, sizeof(esc_id), NULL);
	lws_json_purify(esc_name, of->name, sizeof(esc_name), NULL);

	n = lws_snprintf(msg, msg_len, "{\"type\":\"remote_capabilities\","
			 "\"target\":\"%s\",\"name\":\"%s\",\"payload\":\"%s\"}",
			 esc_id, esc_name, esc);

	mixer_send_text(to, msg, (size_t)n);

	free(msg);
	free(esc);
}

static void start_room_timers(struct mixer_room *r);

static void
sul_presence_cb(lws_sorted_usec_list_t *sul)
{
	struct mixer_room *r = lws_container_of(sul, struct mixer_room, sul_presence);
	/* Check presence... for now just reschedule */
	start_room_timers(r);
}

static void
start_room_timers(struct mixer_room *r)
{
	/* Mixer loop is now handled by worker thread */
	lws_sul_schedule(we_ops->get_context(r->vhd->vhd), 0, &r->sul_presence, sul_presence_cb, 1 * LWS_US_PER_SEC);
}

static void
mixer_on_media(struct lws *wsi_ws, int tid, const uint8_t *buf, size_t len, int marker, uint32_t timestamp)
{
	struct pss_webrtc *pss = (struct pss_webrtc *)lws_wsi_user(wsi_ws);
	struct participant *pss_p = (struct participant *)we_ops->get_user_data(pss);
	struct mixer_msg msg;

	if (!pss_p || !pss_p->session)
		return;

	if (tid == 206 && marker == 1) {
		/* Received proxy PLI from webrtc plugin. Force a keyframe. */
		if (pss_p->room) {
			lwsl_notice("%s: Received PLI proxy from '%s', forcing keyframe\n", __func__, pss_p->name);
			mixer_force_keyframe(pss_p->room);
		}
		return;
	}

	/* Create Message */
	memset(&msg, 0, sizeof(msg));
	msg.type = MSG_VIDEO_FRAME;
	/* Determine Type */
	uint8_t apt = we_ops->get_audio_pt ? we_ops->get_audio_pt(pss) : 0;
	if (apt && tid == apt) {
		msg.type = MSG_AUDIO_FRAME;
	}
#if 0
	static int dbg_audio = 0;
	static int dbg_video = 0;

	if (tid == apt) {
		if (marker || (dbg_audio++ % 50 == 0)) {
			lwsl_notice("%s: Inbound AUDIO FRAME (tid %d, apt %d), len %zu\n", __func__, tid, apt, len);
		}
	} else {
		if (marker || (dbg_video++ % 50 == 0)) {
			lwsl_notice("%s: Inbound VIDEO FRAME (tid %d, apt %d, len %zu, marker %d)\n", __func__, tid, apt, len, marker);
		}
	}
#endif
	if (msg.type == MSG_VIDEO_FRAME) {
		msg.seq = we_ops->get_seq_video ? we_ops->get_seq_video(pss) : 0;
		if (pss_p->expect_valid && (uint16_t)(pss_p->expect_seq) != msg.seq) {
			lws_usec_t now = lws_now_usecs();
			if (now - pss_p->last_pli_req > 500000) {
				lwsl_notice("%s: Requesting PLI from '%s' due to seq mismatch\n", __func__, pss_p->name);
				if (we_ops->send_pli)
					we_ops->send_pli(pss);
				pss_p->last_pli_req = now;
			}
		}
		pss_p->expect_seq = msg.seq + 1;
		pss_p->expect_valid = 1;

		msg.codec = 0;
		/* Resolve PT to Codec */
		// We need access to negotiated PTs.
		// struct pss_webrtc has them but they are private to protocol_lws_webrtc.
		// But we have we_ops accessors if they exist?
		// Actually struct pss_webrtc is defined in protocol_lws_webrtc.c but NOT public header?
		// Wait, pss IS defined in public header? No.
		// But we cast lws_wsi_user(wsi) to struct pss_webrtc* in line 151.
		// This implies we have the definition of struct pss_webrtc available here?
		/*
		 * Q-35: classify the incoming RTP payload type into a codec.
		 * We reach into the webrtc plugin's pss only through the
		 * we_ops vtable (get_video_pt_*), which is the supported
		 * abstraction across the two plugins.
		 */
		if (we_ops && we_ops->get_video_pt_h264 && tid == we_ops->get_video_pt_h264(pss)) {
			msg.codec = LWS_CODEC_H264;
		} else if (we_ops && we_ops->get_video_pt_av1 && tid == we_ops->get_video_pt_av1(pss)) {
			msg.codec = LWS_CODEC_AV1;
		} else if (we_ops && we_ops->get_video_pt && tid == we_ops->get_video_pt(pss)) {
			/* Match primary if specific is not hit - but what codec is the primary? */
			if (we_ops->get_video_pt_av1 && we_ops->get_video_pt(pss) == we_ops->get_video_pt_av1(pss))
				msg.codec = LWS_CODEC_AV1;
			else
				msg.codec = LWS_CODEC_H264; /* If in doubt, assume H264 standard */
		} else {
			/* We did not find an explicit match. Default to the primary negotiated video codec. */
			if (we_ops && we_ops->get_video_pt && we_ops->get_video_pt_av1 &&
			    we_ops->get_video_pt(pss) == we_ops->get_video_pt_av1(pss))
				msg.codec = LWS_CODEC_AV1;
			else
				msg.codec = LWS_CODEC_H264;
		}
#if 0
		static int dbg_video = 0;
		if (marker || (dbg_video++ % 50 == 0))
			lwsl_notice("%s: Queuing VIDEO frame (pt %d -> codec %d, len %zu, marker %d)\n", __func__, tid, msg.codec, len, marker);
#endif
	}

	msg.payload = malloc(len);
	if (!msg.payload) return;
	memcpy(msg.payload, buf, len);
	msg.len = len;

	msg.timestamp = timestamp;
	msg.marker = marker;

	lws_mutex_lock(pss_p->session->mutex);
	if (lws_ring_insert(pss_p->session->ring_input, &msg, 1) != 1) {
		free(msg.payload);
		lwsl_debug("%s: Ring Buffer Full! Dropping packet.\n", __func__);
		pss_p->session->gst_qos_drops++;
	}
	lws_mutex_unlock(pss_p->session->mutex);
}

static int
callback_mixer(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct vhd_mixer *vhd = (struct vhd_mixer *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	const struct lws_protocols *p_plugin;

	switch (reason) {
		case LWS_CALLBACK_WSI_CREATE:
		case LWS_CALLBACK_WSI_DESTROY:
			break;

		case LWS_CALLBACK_PROTOCOL_INIT:
			if (!in) return 0;

			if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
				return 0;

			vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi), sizeof(struct vhd_mixer));
			if (!vhd) return -1;

			{
				const struct lws_protocol_vhost_options *pvo;

				vhd->max_rooms = MIXER_DEFAULT_MAX_ROOMS;
				pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in,
						     "max-rooms");
				if (pvo) {
					int n = atoi(pvo->value);

					if (n > 0 && n <= 4096)
						vhd->max_rooms = n;
					else
						lwsl_warn("%s: ignoring bogus max-rooms '%s'\n",
							  __func__, pvo->value);
				}

				pvo = lws_pvo_search(
					(const struct lws_protocol_vhost_options *)in, "gstreamer-pipeline");
				if (pvo) {
					lws_strncpy(vhd->pipeline_template, pvo->value, sizeof(vhd->pipeline_template));
				} else {
					lws_strncpy(vhd->pipeline_template, "compositor name=comp ! videoconvert ! videoscale ! video/x-raw,width=1280,height=720,framerate=25/1 ! x264enc name=venc tune=zerolatency speed-preset=ultrafast byte-stream=true config-interval=1 ! appsink name=outsink sync=false async=false", sizeof(vhd->pipeline_template));
				}
			}

			p_plugin = lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-webrtc");
			if (!p_plugin) {
				lwsl_err("%s: lws-webrtc protocol not found on vhost\n", __func__);
				return -1;
			}
			we_ops = (const struct lws_webrtc_ops *)p_plugin->user;

			void *pv = lws_protocol_vh_priv_get(lws_get_vhost(wsi), p_plugin);
			if (pv != p_plugin->user)
				vhd->vhd = (struct vhd_webrtc *)pv;
			else
				vhd->vhd = NULL;

			if (!we_ops || we_ops->abi_version != LWS_WEBRTC_OPS_ABI_VERSION) {
				lwsl_err("%s: Incompatible lws-webrtc ABI\n", __func__);
				return -1;
			}

			if (!vhd->vhd) {
				lwsl_err("%s: lws-webrtc vhost data not found (init order?)\n", __func__);
				return -1;
			}

			we_ops->set_on_media(vhd->vhd, mixer_on_media);

			/* Initialize Worker Threading */
			lws_mutex_init(vhd->mutex_rx);
			/*
			 * Session add/remove control ring.  It only has to
			 * absorb one 20ms worker tick's worth of connect and
			 * disconnect events; if it ever does overflow,
			 * deinit_participant_media() falls back to orphaning
			 * the session for the worker to reap.
			 */
			vhd->ring_rx = lws_ring_create(sizeof(struct mixer_msg), 256, NULL);

			vhd->worker_running = 1;
			if (pthread_create(&vhd->worker_thread, NULL, media_worker_thread, vhd)) {
				lwsl_err("%s: Failed to create worker thread\n", __func__);
				return -1;
			}

			/* Stats timer is fine on LWS thread */
			lws_sul_schedule(lws_get_context(wsi), 0, &vhd->sul_stats, sul_stats_cb, 1 * LWS_US_PER_SEC);

			break;

		case LWS_CALLBACK_PROTOCOL_DESTROY:
			if (vhd) {
				lws_sul_cancel(&vhd->sul_stats);
				if (vhd->worker_running) {
					vhd->worker_running = 0;
					pthread_join(vhd->worker_thread, NULL);

					/*
					 * We are the only thread left now, so
					 * finish the worker's outstanding work
					 * ourselves: its sessions still point
					 * into the rooms' pipelines.
					 */
					mixer_worker_drain(vhd);

					lws_mutex_destroy(vhd->mutex_rx);
					lws_ring_destroy(vhd->ring_rx);
				}

				/*
				 * The worker is joined and has let go of them,
				 * so the rooms are ours again and it is safe to
				 * tear them down.
				 */
				lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
						lws_dll2_get_head(&vhd->rooms)) {
					struct mixer_room *r = lws_container_of(d,
							struct mixer_room, list);

					lws_sul_cancel(&r->sul_presence);
					lws_dll2_remove(&r->list);
					if (!lws_dll2_is_detached(&r->w_list))
						lws_dll2_remove(&r->w_list);
					mixer_room_deinit(r);
					free(r);
				} lws_end_foreach_dll_safe(d, d1);
				vhd->num_rooms = 0;
			}
			break;

		case LWS_CALLBACK_ESTABLISHED:
			{
				struct pss_webrtc *pss = (struct pss_webrtc *)lws_wsi_user(wsi);
				char room_name[64], arg[80];
				struct mixer_room *rm;
				struct participant *p;
				int n;

				if (we_ops->shared_callback(wsi, reason, user, in, len, vhd->vhd))
					return -1;

				if (!pss) {
					lwsl_wsi_warn(wsi, "pss is NULL");
					return -1;
				}
				if (!vhd) {
					lwsl_wsi_warn(wsi, "vhd is NULL");
					return -1;
				}

				/*
				 * `in` for LWS_CALLBACK_ESTABLISHED is the SSL *
				 * for the connection, NOT a string (see
				 * lws-callbacks.h): this used to strdup() and
				 * strcmp() it as the room name, walking an
				 * unrelated heap object.  The room comes from the
				 * ws URI's "?room=" arg instead --- the ah is
				 * still attached at this point --- and is
				 * validated before we use it.
				 */
				lws_strncpy(room_name, "default", sizeof(room_name));
				n = lws_get_urlarg_by_name_safe(wsi, "room=", arg,
								sizeof(arg));
				if (n > 0) {
					if (mixer_room_name_ok(arg, (size_t)n))
						lws_strncpy(room_name, arg,
							    sizeof(room_name));
					else
						lwsl_wsi_notice(wsi, "bad room arg, using default");
				}

				p = calloc(1, sizeof(*p));
				if (!p) {
					lwsl_wsi_warn(wsi, "p is NULL");
					return -1;
				}
				p->pss = pss;
				p->wsi = wsi;

				/* Initialize underlying WebRTC PSS */
				/* Shared callback handles PSS init and list addition now */

				we_ops->set_user_data(pss, p);

				rm = get_or_create_room(vhd, room_name);
				if (!rm) {
					lwsl_err("%s: Failed to get/create room\n", __func__);
					goto est_fail;
				}

				/*
				 * The first participant in a room is its
				 * controller, see README.md.
				 */
				p->controller = !lws_dll2_get_head(&rm->participants);

				/* Create Shared Session */
				p->session = mixer_media_session_create(vhd);
				if (!p->session) {
					lwsl_err("%s: Failed to create media session\n",
							__func__);
					goto est_fail;
				}

				/*
				 * The participant's opaque, server-assigned
				 * handle.  This, not the display name it picks
				 * for itself, is how other peers address it,
				 * and it is fixed for the life of the wsi.
				 */
				lws_snprintf(p->id, sizeof(p->id), "u%u",
					     p->session->id);
				lws_strncpy(p->name, p->id, sizeof(p->name));

				if (we_ops && we_ops->get_media) {
					p->session->media = we_ops->get_media(p->pss);
					if (p->session->media && we_ops->media_ref)
						we_ops->media_ref(p->session->media);
				}

				mixer_media_session_set_ident(p->session, p->name, "");

				/* Signal Worker to Add */
				if (mixer_media_session_publish(p->session, rm)) {
					mixer_media_session_unref(p->session);
					p->session = NULL;
					goto est_fail;
				}

				p->room = rm;
				lws_dll2_add_tail(&p->list, &rm->participants);
				start_room_timers(rm);
				p->joined = 0;
				p->session->joined = 0;

				/* Notify others */
				broadcast_client_list(rm, NULL);
				break;

est_fail:
				/*
				 * Returning non-zero from ESTABLISHED still
				 * gets us a LWS_CALLBACK_CLOSED, so the pss
				 * must not be left pointing at the participant
				 * we are about to free.
				 */
				we_ops->set_user_data(pss, NULL);
				free(p);

				return -1;
			}

			/* ... (RECEIVE case remains unchanged) ... */

		case LWS_CALLBACK_RECEIVE:
			{
				const char *v;
				size_t al;
				struct participant *p = (struct participant *)we_ops->get_user_data((struct pss_webrtc *)user);
				int is_capabilities = 0;
				int n;

				// lwsl_notice("%s: RECEIVE (len %zu)\n", __func__, len);

				n = we_ops->shared_callback(wsi, reason, user, in, len, vhd->vhd);

				if (p && p->session && we_ops && we_ops->get_video_pt) {
					lws_mutex_lock(p->session->mutex);
					uint8_t pt = we_ops->get_video_pt(p->pss);
					p->session->can_rx_av1 = (pt != 0 && we_ops->get_video_pt_av1 && pt == we_ops->get_video_pt_av1(p->pss)) ? 1 : 0;
					p->session->can_rx_h264 = (pt != 0 && we_ops->get_video_pt_h264 && pt == we_ops->get_video_pt_h264(p->pss)) ? 1 : 0;
					lws_mutex_unlock(p->session->mutex);
				}

				if (n) return n;

				if (!p) break;

				/* Check type first to avoid false positives on 'name' inside capabilities/etc */
				v = lws_json_simple_find((const char *)in, len, "\"type\":", &al);
				if (v && al == 12 && !strncmp(v, "capabilities", 12))
					is_capabilities = 1;

				if (is_capabilities) {
					/* Store the raw JSON blob of capabilities for this participant */
					v = lws_json_simple_find((const char *)in, len, "\"controls\":", &al);
					if (!v) {
						lwsl_err("%s: 'controls' key not found in capabilities message\n", __func__);
					} else if (len > MIXER_MAX_CAPS_LEN) {
						/*
						 * We keep one of these per participant per kind
						 * and relay it, so it has to be bounded well
						 * below the 32KB rx_buffer_size.
						 */
						lwsl_warn("%s: capabilities blob of %zu too big, dropped\n",
								__func__, len);
					} else {
						size_t kl;
						const char *kind = lws_json_simple_find((const char *)in, len, "\"kind\":", &kl);
						int is_audio = (kind && kl == 5 && !strncmp(kind, "audio", 5));
						char **target_cap = is_audio ? &p->capabilities_audio : &p->capabilities_video;

						if (*target_cap) free(*target_cap);

						*target_cap = malloc(len + 1);
						if (*target_cap) {
							memcpy(*target_cap, in, len);
							(*target_cap)[len] = '\0';
							lwsl_notice("[INSTRUMENT] %s: Stored %s capabilities for '%s' (%zu bytes)\n",
									__func__, is_audio ? "audio" : "video", p->id, len);

							/* Notify all clients about this update immediately */
							broadcast_client_list(p->room, NULL);

							/*
							 * Only the room controller is entitled to
							 * another participant's enumerated device
							 * capabilities; this used to go to
							 * everybody, which was both a disclosure
							 * and an N-way amplifier.
							 */
							lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&p->room->participants)) {
								struct participant *other = lws_container_of(d, struct participant, list);

								if (other != p && mixer_may_control(other, p))
									send_remote_caps(other, p, *target_cap);
							} lws_end_foreach_dll(d);
						}
					}
				} else {
					/* Only update metadata if NOT a capabilities message, to avoid matching nested fields */
					/* Filter out frequent messages from debug log */
					v = lws_json_simple_find((const char *)in, len, "\"type\":", &al);
					int is_spam = 0;
					if (v && ((al >= 15 && !strncmp(v, "presence_report", 15)) ||
								(al >= 5 && !strncmp(v, "stats", 5)))) {
						is_spam = 1;
					}

					if (!is_spam)
						lwsl_warn("%s: RAW RECEIVE (len %zu): %.*s\n", __func__, len, (int)(len > 100 ? 100 : len), (const char *)in);
					/*
					 * The display name is cosmetic only: nothing is
					 * routed by it any more, peers are addressed by
					 * the server-assigned p->id.
					 */
					v = lws_json_simple_find((const char *)in, len, "\"name\":", &al);
					if (v && !mixer_json_str(p->name, sizeof(p->name), v, al)) {
						lwsl_notice("%s: Name update: '%s'\n", __func__, p->name);
						if (p->session)
							mixer_media_session_set_ident(p->session,
									p->name, NULL);
					}

					v = lws_json_simple_find((const char *)in, len, "\"stats\":", &al);
					if (v && !mixer_json_str(p->client_stats,
								 sizeof(p->client_stats), v, al)) {
						lws_snprintf(p->stats, sizeof(p->stats), "%s | Rx: %dfps",
								p->client_stats, p->session ? p->session->current_fps : 0);
						if (p->session)
							mixer_media_session_set_ident(p->session,
									NULL, p->stats);
						broadcast_client_list(p->room, NULL);
					}

					v = lws_json_simple_find((const char *)in, len, "\"out_only\":", &al);
					if (v && al == 4 && !strncmp(v, "true", 4)) {
						p->out_only = 1;
						if (p->session)
							p->session->out_only = 1;
						lwsl_notice("%s: Participant '%s' is OUT-ONLY\n", __func__, p->id);
					}
				}

				/*
				 * Re-parse type for dispatching.
				 *
				 * `tal` keeps the *type* value's length: the
				 * handlers below each call lws_json_simple_find()
				 * again for their own members, which clobbers `al`,
				 * so testing `al` against `v` after the first of
				 * them fired was comparing the type string against
				 * some other member's length.
				 *
				 * lws_json_simple_find() strips the quotes, so all
				 * of these compare against the bare token.
				 */
				v = lws_json_simple_find((const char *)in, len, "\"type\":", &al);
				if (v) {
					size_t tal = al;
					int is_join = (tal == 4 && !strncmp(v, "join", 4));

					/*
					 * Handle video_mute: {"type":"video_mute","muted":true/false}
					 *
					 * Match the type value exactly: strstr() over the
					 * rest of the message took this branch for any
					 * message that merely contained the substring.
					 */
					if (tal == 10 && !strncmp(v, "video_mute", 10)) {
						const char *m = lws_json_simple_find((const char *)in, len, "\"muted\":", &al);
						if (m && p->session) {
							p->session->video_muted = (al == 4 && !strncmp(m, "true", 4));
							lwsl_notice("[INSTRUMENT] %s: Participant '%s' video_muted=%d\n", __func__, p->id, p->session->video_muted);
							broadcast_client_list(p->room, NULL);
						}
					}

					/* Handle request_debug_log: {"type":"request_debug_log"} */
					if (tal == 17 && !strncmp(v, "request_debug_log", 17)) {

						lwsl_notice("%s: Sending debug log to '%s'\n", __func__, p->name);
						if (p->pss && p->pss->connection_log_len > 0) {
							size_t esc_len = (p->pss->connection_log_len * 2) + 1;
							size_t msg_len = esc_len + 128;
							char *msg = malloc(msg_len);
							if (msg) {
								char *esc_log = malloc(esc_len);
								if (esc_log) {
									lws_json_purify(esc_log, p->pss->connection_log, (int)esc_len, NULL);
									int rn = lws_snprintf(msg, msg_len,
										"{\"type\":\"debug_log\",\"log\":\"%s\"}", esc_log);
									mixer_send_text(p, msg, (size_t)rn);
									free(esc_log);
								}
								free(msg);
							}
						} else if (p->pss) {
							/* Send back a guaranteed response even if connection_log_len is 0 */
							const char *fback = "{\"type\":\"debug_log\",\"log\":\"No server connection logs were recorded prior to failure.\"}";
							mixer_send_text(p, fback, strlen(fback));
						}
					}

					/*
					 * Handle set_control:
					 * {"type":"set_control","target":"<id>","id":...,"val":...}
					 *
					 * lws_json_simple_find() strips the quotes, so the
					 * value is exactly "set_control".
					 */
					if (tal == 11 && !strncmp(v, "set_control", 11)) {
						const char *target = lws_json_simple_find((const char *)in, len, "\"target\":", &al);
						if (target) {
							char target_id[sizeof(p->id)];
							struct participant *tp;

							if (mixer_json_str(target_id, sizeof(target_id),
									   target, al))
								break;

							tp = find_participant_by_id(p->room, target_id);
							if (!tp || !tp->pss) {
								lwsl_warn("%s: set_control: no such participant\n",
										__func__);
								break;
							}

							/*
							 * This drives the target's camera and
							 * microphone device settings, so a peer
							 * may only aim it at itself unless it is
							 * the room's controller.
							 */
							if (!mixer_may_control(p, tp)) {
								lwsl_warn("%s: '%s' not entitled to control '%s'\n",
										__func__, p->id, tp->id);
								break;
							}

							/*
							 * The target only looks at "type", "id" and
							 * "val", and ignores "target", so the
							 * message can be forwarded as-is --- it
							 * goes to a peer that has just been shown
							 * to be a legitimate destination for it.
							 */
							mixer_send_text(tp, (const char *)in, len);
							lwsl_notice("%s: Forwarded set_control from '%s' to '%s'\n",
									__func__, p->id, tp->id);
						}
					}

					if (is_join) {
						if (!p->session && p->room) {
							lwsl_notice("%s: Recreating media session for re-joiner '%s'\n", __func__, p->id);
							p->session = mixer_media_session_create(p->room->vhd);
							if (!p->session) {
								lwsl_err("%s: Failed to recreate session for '%s'\n", __func__, p->id);
							} else {
								if (we_ops && we_ops->get_media) {
									p->session->media = we_ops->get_media(p->pss);
									if (p->session->media && we_ops->media_ref)
										we_ops->media_ref(p->session->media);
								}

								p->session->out_only = p->out_only;
								mixer_media_session_set_ident(p->session,
										p->name, p->stats);

								/*
								 * If the worker cannot take it, release
								 * it completely rather than leaving a
								 * session the worker does not know
								 * about --- LWS_CALLBACK_CLOSED would
								 * later post a MSG_REMOVE_SESSION for
								 * a reference that was never handed
								 * over.
								 */
								if (mixer_media_session_publish(p->session,
										p->room)) {
									mixer_media_session_unref(p->session);
									p->session = NULL;
								}
							}
						}

						/* The WebRTC offer might have been processed just before this join message,
						   meaning pss->media is now allocated. Update the session's media pointer
						   if it is currently NULL. */
						if (p->session && !p->session->media && we_ops && we_ops->get_media) {
							p->session->media = we_ops->get_media(p->pss);
							if (p->session->media && we_ops->media_ref)
								we_ops->media_ref(p->session->media);
						}

						p->joined = 1;
						if (p->session) p->session->joined = 1;
						p->presence_missed = 0;
						lwsl_notice("%s: Participant '%s' JOINED\n", __func__, p->name);

						/* Play Join Sound */
						if (p->room) {
							play_sound(p->room, &p->room->vhd->sfx_join, p);
							mixer_force_keyframe(p->room);
						}

						if (p->room)
							broadcast_client_list(p->room, NULL);

						/* Send Peer IP to client so it can use it for STUN candidates */
						{
							char peer_ip[64];
							char json_buf[LWS_PRE + 256];
							const char *ip = lws_get_peer_simple(wsi, peer_ip, sizeof(peer_ip));
							if (ip) {
								int n = lws_snprintf(json_buf, sizeof(json_buf), "{\"type\":\"peer_ip\",\"ip\":\"%s\"}", ip);
								if (p->pss) {
									mixer_send_text(p, json_buf, (size_t)n);
									lwsl_notice("%s: Sent peer_ip '%s' to '%s'\n", __func__, ip, p->name);
								}
							}
						}

						if (p->room) {
							/* Send Chat History */
							lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&p->room->chat_history)) {
								struct chat_message *cm = lws_container_of(d, struct chat_message, list);
								char json_buf[LWS_PRE + 2048];
								char esc_sender[384], esc_text[1024];

								lws_json_purify(esc_sender, cm->sender, sizeof(esc_sender), NULL);
								lws_json_purify(esc_text, cm->text, sizeof(esc_text), NULL);

								lws_snprintf(json_buf, sizeof(json_buf),
										"{\"type\":\"chat\",\"sender\":\"%s\",\"text\":\"%s\"}",
										esc_sender, esc_text);
								if (p->pss)
									mixer_send_text(p, json_buf, strlen(json_buf));
							} lws_end_foreach_dll(d);

							/*
							 * Send cached capabilities from other
							 * participants --- but only to the room
							 * controller, which is the only peer
							 * entitled to them.
							 */
							lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&p->room->participants)) {
								struct participant *other = lws_container_of(d, struct participant, list);

								if (other == p || !mixer_may_control(p, other))
									continue;

								send_remote_caps(p, other, other->capabilities_video);
								send_remote_caps(p, other, other->capabilities_audio);
							} lws_end_foreach_dll(d);
						}
					} else if (tal == 5 && !strncmp(v, "leave", 5)) {
						/* Handle explicit leave without closing WS */
						if (p->joined) {
							p->joined = 0;
							if (p->session) p->session->joined = 0;
							if (p->room->active_video == p) p->room->active_video = NULL;
							lwsl_notice("%s: Participant '%s' LEFT (persistent)\n", __func__, p->name);

							/* Play Leave Sound */
							play_sound(p->room, &p->room->vhd->sfx_leave, NULL);

							/* Free heavy resources so we don't leak or reuse stale state */
							deinit_participant_media(p);

							/* Clear any exclusion references to this participant */
							lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&p->room->playing_sounds)) {
								struct active_sound *as = lws_container_of(d, struct active_sound, list);
								if (as->exclude_p == p) as->exclude_p = NULL;
							} lws_end_foreach_dll_safe(d, d1);

							broadcast_client_list(p->room, NULL);
						}
					} else if (tal == 15 && !strncmp(v, "presence_report", 15)) {
						/* {"type":"presence_report","joined":true} */
						const char *j_val = lws_json_simple_find((const char *)in, len, "\"joined\":", &al);
						// lwsl_notice("%s: PRESENCE REPORT from '%s' (joined=%d, current_missed=%d)\n", __func__, p->name, p->joined, p->presence_missed);
						if (j_val) {
							int is_joined = 0;
							if (al >= 4 && !strncmp(j_val, "true", 4)) is_joined = 1;

							if (is_joined) {
								p->presence_missed = 0;
							} else {
								/* They report NOT joined */
								if (p->joined) {
									lwsl_notice("%s: Client reported NOT joined (was joined)\n", __func__);
									p->joined = 0;
									if (p->room->active_video == p) p->room->active_video = NULL;

									/* Play Leave Sound (maybe? yes if they were joined) */
									play_sound(p->room, &p->room->vhd->sfx_leave, NULL);

									broadcast_client_list(p->room, NULL);
								}
							}
						}
					} else if (tal == 12 && !strncmp(v, "request_caps", 12)) {

						/* {"type":"request_caps","target":"<id>"} */
						const char *tgt;
						lws_usec_t now = lws_now_usecs();

						/*
						 * Each of these makes us allocate and queue
						 * the whole of somebody's capability blob in
						 * response to a ~40 byte request, so it is a
						 * fat amplifier: rate limit it.
						 */
						if (p->last_caps_req &&
						    now - p->last_caps_req < MIXER_CAPS_REQ_MIN_INTERVAL_US) {
							lwsl_notice("%s: request_caps from '%s' rate limited\n",
									__func__, p->id);
							break;
						}
						p->last_caps_req = now;

						tgt = lws_json_simple_find((const char *)in, len, "\"target\":", &al);
						if (tgt) {
							char target_id[sizeof(p->id)];
							struct participant *tp;

							if (mixer_json_str(target_id, sizeof(target_id), tgt, al))
								break;

							tp = find_participant_by_id(p->room, target_id);
							if (!tp) {
								lwsl_warn("%s: request_caps: no such participant\n",
										__func__);
								break;
							}

							if (!mixer_may_control(p, tp)) {
								lwsl_warn("%s: '%s' not entitled to '%s' capabilities\n",
										__func__, p->id, tp->id);
								break;
							}

							send_remote_caps(p, tp, tp->capabilities_video);
							send_remote_caps(p, tp, tp->capabilities_audio);
						}

					} else if (tal == 4 && !strncmp(v, "chat", 4)) {
						/* {"type":"chat","text":"..."} */
						const char *txt = lws_json_simple_find((const char *)in, len, "\"text\":", &al);

						/*
						 * Chat enters the room's history and is
						 * replayed to everybody who joins later, so
						 * only accept it from a participant that has
						 * actually joined the room.
						 */
						if (!p->joined) {
							lwsl_warn("%s: chat from '%s' which has not joined\n",
									__func__, p->id);
							break;
						}

						if (txt && al > 0 && al <= 1024) {
							struct chat_message *cm;
							size_t txt_len = al;
							char *txt_dup;

							txt_dup = malloc(txt_len + 1);
							if (!txt_dup) return -1;
							memcpy(txt_dup, txt, txt_len);
							txt_dup[txt_len] = '\0';

							cm = malloc(sizeof(*cm));
							if (!cm) { free(txt_dup); return -1; }
							memset(cm, 0, sizeof(*cm));

							cm->text = txt_dup;
							cm->sender = strdup(p->name[0] ? p->name : "Anonymous");
							cm->timestamp = (uint64_t)lws_now_usecs();

							/* Add to history */
							lws_dll2_add_tail(&cm->list, &p->room->chat_history);

							/* Prune if > 20 */
							if (lws_dll2_count(&p->room->chat_history) > 20) {
								struct chat_message *old = lws_container_of(lws_dll2_get_head(&p->room->chat_history), struct chat_message, list);
								lws_dll2_remove(&old->list);
								free(old->sender);
								free(old->text);
								free(old);
							}

							/* Broadcast */
							{
								char json_buf[LWS_PRE + 2048];
								char esc_sender[384], esc_text[1024];
								int tlen;

								lws_json_purify(esc_sender, cm->sender, sizeof(esc_sender), NULL);
								lws_json_purify(esc_text, cm->text, sizeof(esc_text), NULL);

								tlen = lws_snprintf(json_buf, sizeof(json_buf),
										"{\"type\":\"chat\",\"sender\":\"%s\",\"text\":\"%s\"}",
										esc_sender, esc_text);

								struct broadcast_ctx bctx = { 0 };
								bctx.room = p->room;
								bctx.text = json_buf;
								bctx.len = (size_t)tlen;
								bctx.require_joined = 1;
								bctx.exclude = NULL; /* Send to everyone including sender */

								lws_dll2_foreach_safe(&p->room->participants, &bctx, broadcast_text_iter);
							}
						}
					}
				}
			}
			break;

			break;

		case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
			if (!vhd)
				break;

			/* Also let shared webrtc handle its own service cancellations */
			if (vhd->vhd && we_ops && we_ops->shared_callback)
				we_ops->shared_callback(wsi, reason, user, in, len, vhd->vhd);
			break;

		case LWS_CALLBACK_CLOSED:
			{
				struct pss_webrtc *pss = (struct pss_webrtc *)user;
				struct participant *p = NULL;
				if (pss && we_ops && we_ops->get_user_data) {
					p = (struct participant *)we_ops->get_user_data(pss);
				}

				if (p) {
					lwsl_notice("%s: Cleaning up participant '%s' on CLOSE\n", __func__, p->name);

					if (p->joined && p->room) {
						p->joined = 0;
						if (p->room->active_video == p)
							p->room->active_video = NULL;

						/* Play Leave Sound */
						play_sound(p->room, &p->room->vhd->sfx_leave, NULL);
					}

					deinit_participant_media(p);

					if (p->room) {
						/* Clear any exclusion references to this participant */
						lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&p->room->playing_sounds)) {
							struct active_sound *as = lws_container_of(d, struct active_sound, list);
							if (as->exclude_p == p) as->exclude_p = NULL;
						} lws_end_foreach_dll_safe(d, d1);

						lws_dll2_remove(&p->list);

						/*
						 * If the controller left, hand the role to
						 * whoever is now at the head of the room, so
						 * the room does not silently become one where
						 * nobody may drive remote device controls.
						 */
						if (p->controller) {
							struct lws_dll2 *h = lws_dll2_get_head(
									&p->room->participants);

							if (h)
								lws_container_of(h, struct participant,
										 list)->controller = 1;
						}

						broadcast_client_list(p->room, NULL);
					}

					if (p->capabilities_video) free(p->capabilities_video);
					if (p->capabilities_audio) free(p->capabilities_audio);

					we_ops->set_user_data(pss, NULL);
					free(p);
				}

				if (vhd && vhd->vhd && we_ops && we_ops->shared_callback)
					return we_ops->shared_callback(wsi, reason, user, in, len, vhd->vhd);
				break;
			}

		case LWS_CALLBACK_SERVER_WRITEABLE:
			return we_ops->shared_callback(wsi, reason, user, in, len, vhd->vhd);

		default:
			if (vhd && vhd->vhd && we_ops && we_ops->shared_callback)
				return we_ops->shared_callback(wsi, reason, user, in, len, vhd->vhd);
			break;
	}

	return 0;
}

LWS_VISIBLE const struct lws_protocols mixer_protocols[] = {
	{"lws-webrtc-mixer", callback_mixer, sizeof(struct pss_webrtc), 32768, 0, NULL, 0},
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t lws_webrtc_mixer = {
	.hdr = {
		.name = "lws webrtc mixer",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
		.priority = 90,
	},
	.protocols = mixer_protocols,
	.count_protocols = LWS_ARRAY_SIZE(mixer_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
