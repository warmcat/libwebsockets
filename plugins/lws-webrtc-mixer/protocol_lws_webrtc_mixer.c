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

#include "../protocol_lws_webrtc.h"
#include "mixer-media.h"
#include <libwebsockets/lws-rtp.h>

const struct lws_webrtc_ops *we_ops;

static struct mixer_room *
get_or_create_room(struct vhd_mixer *vhd, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->rooms)) {
		struct mixer_room *r = lws_container_of(d, struct mixer_room, list);
		if (!strcmp(r->name, name))
			return r;
	} lws_end_foreach_dll(d);

	struct mixer_room *r = malloc(sizeof(*r));
	if (!r) return NULL;
	memset(r, 0, sizeof(*r));
	lws_strncpy(r->name, name, sizeof(r->name));
	r->vhd = vhd;

	/* Default audio limits */
	r->audio_info.squelch_level = 1000.0;
	r->audio_info.max_energy = 327680.0;
	r->audio_info.sample_stride = 48;

	r->master_w = LWS_RTP_VIDEO_WIDTH_1080P;
	r->master_h = LWS_RTP_VIDEO_HEIGHT_1080P;

	/* Initialize Performance Tracker (2 levels: 0=High Quality, 1=Fallback) */
	/* 5s short-term EWMA for quick drops, 60s long-term EWMA for sustained recovery */
	r->adapt_h264 = lws_adapt_create(2, 5 * LWS_US_PER_SEC, 60 * LWS_US_PER_SEC);

	if (mixer_room_init(r) < 0) {
		lws_adapt_destroy(&r->adapt_h264);
		free(r);
		return NULL;
	}

	lws_dll2_add_tail(&r->list, &vhd->rooms);

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
				we_ops->send_text(p->pss, json, strlen(json));
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

						p->session->current_fps = (int)((diff * 1000000) / interval_us);
						p->session->last_fps_check = now;
						p->session->last_processed_frames_count = p->session->processed_frames_count;

						if (p->client_stats[0]) {
							lws_snprintf(p->stats, sizeof(p->stats), "%s | Rx: %dx%d %dfps",
									p->client_stats, p->session->last_dec_w, p->session->last_dec_h, p->session->current_fps);
						} else {
							lws_snprintf(p->stats, sizeof(p->stats), "Rx: %dx%d %dfps",
									p->session->last_dec_w, p->session->last_dec_h, p->session->current_fps);
						}
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
		we_ops->send_text(p->pss, ctx->text, ctx->len);
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

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{\"name\":\"%s\",\"joined\":%s,\"stats\":\"%s\"}",
				part->name, part->joined ? "true" : "false", part->stats);
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

	if (r->lm_ops && r->lm_ops->get_json) {
		json = r->lm_ops->get_json(r->lm_ctx);
	}

	if (!json) return;

	bctx.room = r;
	bctx.text = json;
	bctx.len = strlen(json);
	bctx.require_joined = 0;
	bctx.exclude = NULL;

	lws_dll2_foreach_safe(&r->participants, &bctx, broadcast_text_iter);

	free(json);
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

	/* Create Message */
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
		msg.codec = 0;
		/* Resolve PT to Codec */
		// We need access to negotiated PTs.
		// struct pss_webrtc has them but they are private to protocol_lws_webrtc.
		// But we have we_ops accessors if they exist?
		// Actually struct pss_webrtc is defined in protocol_lws_webrtc.c but NOT public header?
		// Wait, pss IS defined in public header? No.
		// But we cast lws_wsi_user(wsi) to struct pss_webrtc* in line 151.
		// This implies we have the definition of struct pss_webrtc available here?
		// Let's check headers included.
		/* line 151: struct pss_webrtc *pss = ... */
		/* If it compiles, we have the struct definition. */
		/* So we can access pss->pt_video_h264 directly? */
		/* Let's Try. If not, we need we_ops helper. */

		/* Actually, lws-webrtc protocol plugin shares pss layout? */
		/* Or maybe we should use we_ops if available. */
		/* we_ops has get_audio_pt. Does it have get_video_pt? */
		/* Let's assume we can access pss fields if we included the header properly or if we_ops provides it. */
		/* But wait, pss_webrtc is defined in protocol_lws_webrtc.c usually? */
		/* If this file compiles line 151, then pss_webrtc is visible. */

		/* Let's assume we can access pss->pt_video_h264 if visible. */
		/* IF NOT, we might need to rely on passed in tid matching implied functionality. */

		/* Let's hack it: */
		/* If we can't see pss layout, we can't checks pts. */
		/* But we are in the SAME plugin (lws-webrtc-mixer)? No, different checks. */
		/* usage of `struct pss_webrtc` suggests we have it. */

		/* Let's try to access pss->pt_video_h264. */

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
			if (we_ops && we_ops->get_video_pt_av1 && we_ops->get_video_pt(pss) == we_ops->get_video_pt_av1(pss))
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
		lwsl_warn("%s: Ring Buffer Full! Dropping packet.\n", __func__);
		/* Overflow stats? */
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

			vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi), sizeof(struct vhd_mixer));
			if (!vhd) return -1;

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
			vhd->ring_rx = lws_ring_create(sizeof(struct mixer_msg), 64, NULL);

			vhd->worker_running = 1;
			if (pthread_create(&vhd->worker_thread, NULL, media_worker_thread, vhd)) {
				lwsl_err("%s: Failed to create worker thread\n", __func__);
				return -1;
			}

			/* Stats timer is fine on LWS thread */
			lws_sul_schedule(lws_get_context(wsi), 0, &vhd->sul_stats, sul_stats_cb, 1 * LWS_US_PER_SEC);

			break;

		case LWS_CALLBACK_PROTOCOL_DESTROY:
			if (vhd && vhd->worker_running) {
				vhd->worker_running = 0;
				pthread_join(vhd->worker_thread, NULL);
				lws_mutex_destroy(vhd->mutex_rx);
				lws_ring_destroy(vhd->ring_rx);
			}

			// Clean up rooms etc.
			break;

		case LWS_CALLBACK_ESTABLISHED:
			{
				struct pss_webrtc *pss = (struct pss_webrtc *)lws_wsi_user(wsi);
				const char *room_name = (const char *)in;
				struct mixer_room *rm;
				struct participant *p;

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

				lws_snprintf(p->name, sizeof(p->name), "User-%p",
						pss);

				/* Create Shared Session */
				p->session = mixer_media_session_create(vhd, p);
				if (p->session && we_ops && we_ops->get_media) {
					p->session->media = we_ops->get_media(p->pss);
					if (p->session->media && we_ops->media_ref)
						we_ops->media_ref(p->session->media);
				}
				if (!p->session) {
					lwsl_err("%s: Failed to create media session\n",
							__func__);
					free(p);
					return -1;
				}

				/* Signal Worker to Add */
				{
					struct mixer_msg msg;
					memset(&msg, 0, sizeof(msg));
					msg.type = MSG_ADD_SESSION;
					msg.session = p->session;
					msg.payload = strdup(room_name && room_name[0] ? room_name : "default");

					mixer_media_session_ref(p->session); /* +1 for Worker */

					lws_mutex_lock(vhd->mutex_rx);
					lws_ring_insert(vhd->ring_rx, &msg, 1);
					lws_mutex_unlock(vhd->mutex_rx);
				}

				rm = get_or_create_room(vhd, room_name && room_name[0] ? room_name : "default");
				if (rm) {
					p->room = rm;
					lws_dll2_add_tail(&p->list, &rm->participants);
					start_room_timers(rm);
					p->joined = 0;
					if (p->session) p->session->joined = 0;

					/* Notify others */
					broadcast_client_list(rm, NULL);
				} else {
					lwsl_err("%s: Failed to get/create room\n", __func__);
					mixer_media_session_unref(p->session);
					mixer_media_session_unref(p->session);
					free(p);
					return -1;
				}
				break;
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
				if (v && ((al >= 12 && !strncmp(v, "\"capabilities\"", 12)) ||
							(al >= 10 && !strncmp(v, "capabilities", 10)))) {
					is_capabilities = 1;
				}

				if (is_capabilities) {
					/* Store the raw JSON blob of capabilities for this participant */
					lwsl_warn("%s: Processing capabilities for '%s'. Payload len %zu:\n",
							__func__, p->name, len);
					lwsl_hexdump_warn(in, len);

					v = lws_json_simple_find((const char *)in, len, "\"controls\":", &al);
					if (v) {
						if (p->capabilities) free(p->capabilities);

						p->capabilities = malloc(len + 1);
						if (p->capabilities) {
							memcpy(p->capabilities, in, len);
							p->capabilities[len] = '\0';
							lwsl_warn("%s: Stored capabilities for '%s' (%zu bytes)\n", __func__, p->name, len);

							/* Notify all clients about this update immediately */
							broadcast_client_list(p->room, NULL);

							{
								/* Construct notification: {"type":"remote_capabilities","target":"<NAME>","payload":<RAW_JSON>} */
								size_t msg_len = len + 128 + (strlen(p->name) * 6);
								char *msg = malloc(msg_len);
								if (msg) {
									char esc_name[384];
									lws_json_purify(esc_name, p->name, sizeof(esc_name), NULL);

									int n = lws_snprintf(msg, msg_len,
											"{\"type\":\"remote_capabilities\",\"target\":\"%s\",\"payload\":%s}",
											esc_name, p->capabilities);

									if (n > 0 && (size_t)n < msg_len) {
										lwsl_info("%s: Broadcasting capabilities update for '%s' to room (len %d)\n", __func__, p->name, n);
										/* Broadcast to everyone (including self? no, others) */
										lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&p->room->participants)) {
											struct participant *other = lws_container_of(d, struct participant, list);
											if (other->pss)
												we_ops->send_text(other->pss, msg, strlen(msg));
										} lws_end_foreach_dll(d);
									} else {
										lwsl_err("%s: Truncation/Error broadcasting capabilities (n=%d, max=%zu)\n", __func__, n, msg_len);
									}

									free(msg);
								}
							}
						}

					} else {
						lwsl_err("%s: 'controls' key not found in capabilities message\n", __func__);
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
					v = lws_json_simple_find((const char *)in, len, "\"name\":", &al);
					if (v) {
						size_t nl = al;
						if (*v == '\"') { v++; nl -= 2; }
						if (nl >= sizeof(p->name)) nl = sizeof(p->name) - 1;
						memcpy(p->name, v, nl);
						p->name[nl] = '\0';
						lwsl_notice("%s: Name update: '%s'\n", __func__, p->name);
					}

					v = lws_json_simple_find((const char *)in, len, "\"stats\":", &al);
					if (v) {
						size_t nl = al;
						if (*v == '\"') { v++; nl -= 2; }
						if (nl >= sizeof(p->client_stats)) nl = sizeof(p->client_stats) - 1;
						memcpy(p->client_stats, v, nl);
						p->client_stats[nl] = '\0';
						if (p->client_stats[0]) {
							lws_snprintf(p->stats, sizeof(p->stats), "%s | Rx: %dx%d %dfps",
									p->client_stats, p->session ? p->session->last_dec_w : 0,
									p->session ? p->session->last_dec_h : 0,
									p->session ? p->session->current_fps : 0);
						}
						// lwsl_notice("%s: Stats update for '%s': '%s'\n", __func__, p->name, p->stats);
						broadcast_client_list(p->room, NULL);
					}

					v = lws_json_simple_find((const char *)in, len, "\"out_only\":", &al);
					if (v && !strncmp(v, "true", 4)) {
						p->out_only = 1;
						lwsl_notice("%s: Participant '%s' is OUT-ONLY\n", __func__, p->name);
					}
				}

				/* Re-parse type for dispatching (v might be clobbered or we just want clean logic) */
				v = lws_json_simple_find((const char *)in, len, "\"type\":", &al);
				if (v) {
					// lwsl_warn("%s: Received message type: %.*s (len %d)\n", __func__, (int)al, v, (int)al);
					int is_join = 0;
					if (al >= 6 && !strncmp(v, "\"join\"", 6)) is_join = 1;
					if (al >= 4 && !strncmp(v, "join", 4)) is_join = 1;

					if (al >= 5 && !strncmp(v, "\"stats\"", 7)) {
						/* Already handled by stats field check above, but good for explicit typing */
					}

					/* Handle request_caps: {"type":"request_caps","target":"<name>"} */
					if (al >= 12 && !strncmp(v, "\"request_caps\"", 12)) {
						const char *target = lws_json_simple_find((const char *)in, len, "\"target\":", &al);
						if (target) {
							char target_name[64];
							size_t nl = al;
							if (*target == '\"') { target++; nl -= 2; }
							if (nl >= sizeof(target_name)) nl = sizeof(target_name) - 1;
							memcpy(target_name, target, nl);
							target_name[nl] = '\0';

							lwsl_notice("%s: request_caps for '%s'\n", __func__, target_name);

							/* Find target participant */
							struct participant *tp = NULL;
							lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&p->room->participants)) {
								struct participant *other = lws_container_of(d, struct participant, list);
								if (!strcmp(other->name, target_name)) {
									tp = other;
									break;
								}
							} lws_end_foreach_dll(d);

							if (tp) {
								if (tp->capabilities) {
									/* Reply with cached capabilities */
									size_t msg_len = strlen(tp->capabilities) + 128 + (strlen(tp->name) * 6);
									char *msg = malloc(msg_len);
									if (msg) {
										char esc_name[384];
										lws_json_purify(esc_name, tp->name, sizeof(esc_name), NULL);

										int n = lws_snprintf(msg, msg_len,
												"{\"type\":\"remote_capabilities\",\"target\":\"%s\",\"payload\":%s}",
												esc_name, tp->capabilities);
										we_ops->send_text(p->pss, msg, (size_t)n);
										free(msg);
										lwsl_notice("%s: Sent cached caps for '%s' to '%s'\n", __func__, tp->name, p->name);
									}
								} else {
									/* Forward request to target (if it's not out_only? No, out_only can have controls too) */
									/* Actually, out_only means it sends video but doesn't receive video. It absolutely has controls. */
									/* We should forward the request so it can reply.
									   But camshow replies to the MIXER, not the requester.
									   The mixer needs to capture that reply and broadcast/forward it.
									   We already handle that in the 'capabilities' block above.
									   */
									lwsl_notice("%s: No cached caps for '%s', forwarding request...\n", __func__, tp->name);
									if (tp->pss) {
										/* Forward {"type":"request_caps"} */
										const char *fwd = "{\"type\":\"request_caps\"}";
										we_ops->send_text(tp->pss, fwd, strlen(fwd));
									}
								}
							} else {
								lwsl_warn("%s: Target '%s' not found for request_caps\n", __func__, target_name);
							}
						}
					}

					/* Handle set_control: {"type":"set_control","target":"<name>","id":...,"val":...} */
					/* v points to "\"set_control\"" (len 13) or just "set_control" if parser strips quotes?
					   lws_json_simple_find通常returns the value including quotes for strings.
					   So "set_control" is 11 chars + 2 quotes = 13.
					   */
					if (al >= 11 && (
								!strncmp(v, "\"set_control\"", 13) ||
								!strncmp(v, "set_control", 11)
							)) {
						const char *target = lws_json_simple_find((const char *)in, len, "\"target\":", &al);
						if (target) {
							char target_name[64];
							size_t nl = al;
							if (*target == '\"') { target++; nl -= 2; }
							if (nl >= sizeof(target_name)) nl = sizeof(target_name) - 1;
							memcpy(target_name, target, nl);
							target_name[nl] = '\0';

							lwsl_notice("%s: set_control for '%s'\n", __func__, target_name);

							/* Find target participant */
							struct participant *tp = NULL;
							lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&p->room->participants)) {
								struct participant *other = lws_container_of(d, struct participant, list);
								if (!strcmp(other->name, target_name)) {
									tp = other;
									break;
								}
							} lws_end_foreach_dll(d);

							if (tp && tp->pss) {
								/* Forward the whole message? Or reconstruct?
								   The message from frontend is {"type":"set_control","target":"...","id":...,"val":...}
								   Camshow expects {"type":"set_control","id":...,"val":...}
								   It ignores extra fields usually, but let's be safe and forward.
								   Actually, camshow's parser looks for "type":"set_control", "id", "val".
								   It doesn't care about "target". So forwarding raw message is fine.
								   */
								we_ops->send_text(tp->pss, (const char *)in, len);
								lwsl_notice("%s: Forwarded set_control to '%s'\n", __func__, tp->name);
							} else {
								lwsl_warn("%s: Target '%s' not found or not connected for set_control\n", __func__, target_name);
							}
						}
					}

					if (is_join) {
						if (!p->session) {
							lwsl_notice("%s: Recreating media session for re-joiner '%s'\n", __func__, p->name);
							p->session = mixer_media_session_create(p->room->vhd, p);
							if (p->session && we_ops && we_ops->get_media) {
								p->session->media = we_ops->get_media(p->pss);
								if (p->session->media && we_ops->media_ref)
									we_ops->media_ref(p->session->media);
							}
							if (p->session) {
								struct mixer_msg msg;
								memset(&msg, 0, sizeof(msg));
								msg.type = MSG_ADD_SESSION;
								msg.session = p->session;
								msg.payload = strdup(p->room ? p->room->name : "default");

								mixer_media_session_ref(p->session);

								lws_mutex_lock(p->room->vhd->mutex_rx);
								lws_ring_insert(p->room->vhd->ring_rx, &msg, 1);
								lws_mutex_unlock(p->room->vhd->mutex_rx);
							} else {
								lwsl_err("%s: Failed to recreate session for '%s'\n", __func__, p->name);
							}
						}

						p->joined = 1;
						if (p->session) p->session->joined = 1;
						p->presence_missed = 0;
						lwsl_notice("%s: Participant '%s' JOINED\n", __func__, p->name);

						/* Play Join Sound */
						if (p->room)
							play_sound(p->room, &p->room->vhd->sfx_join, p);

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
									we_ops->send_text(p->pss, json_buf, (size_t)n);
									lwsl_notice("%s: Sent peer_ip '%s' to '%s'\n", __func__, ip, p->name);
								}
							}
						}

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
								we_ops->send_text(p->pss, json_buf, strlen(json_buf));
						} lws_end_foreach_dll(d);

						/* Send Cached Capabilities from other participants */
						lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&p->room->participants)) {
							struct participant *other = lws_container_of(d, struct participant, list);
							if (other != p && other->capabilities) {
								size_t msg_len = strlen(other->capabilities) + 128 + (strlen(other->name) * 6);
								char *msg = malloc(msg_len);
								if (msg) {
									char esc_name[384];
									lws_json_purify(esc_name, other->name, sizeof(esc_name), NULL);

									int n = lws_snprintf(msg, msg_len,
											"{\"type\":\"remote_capabilities\",\"target\":\"%s\",\"payload\":%s}",
											esc_name, other->capabilities);
									if (p->pss)
										we_ops->send_text(p->pss, msg, (size_t)n);
									free(msg);
									lwsl_notice("%s: Sent cached caps for '%s' to new joiner '%s'\n", __func__, other->name, p->name);
								}
							}
						} lws_end_foreach_dll(d);
					} else if ((al >= 7 && !strncmp(v, "\"leave\"", 7)) ||
							(al >= 5 && !strncmp(v, "leave", 5))) {
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
					} else if ((al >= 17 && !strncmp(v, "\"presence_report\"", 17)) ||
							(al >= 15 && !strncmp(v, "presence_report", 15))) {
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
					} else if ((al >= 12 && !strncmp(v, "\"capabilities\"", 12)) ||
							(al >= 10 && !strncmp(v, "capabilities", 10))) {
						/* Store and broadcast capabilities */
						lwsl_notice("%s: Received capabilities from '%s'\n", __func__, p->name);

						/* {"type":"capabilities","kind":"video","controls":[...]} */

						/* We want to store the whole message or just the controls?
						   Let's store the whole message so we can just replay it. */
						if (p->capabilities) free(p->capabilities);
						p->capabilities = malloc(len + 1);
						if (p->capabilities) {
							memcpy(p->capabilities, in, len);
							p->capabilities[len] = '\0';
						}

						/* Broadcast to others so they can update UI immediately if watching?
						   Or just let them request it.
						   Let's broadcast a notification or the caps themselves wrapped with owner info. */
						/* Wrapped: {"type":"remote_capabilities","target":"<name>","payload":<original_json>} */
						/* Actually, simply forwarding it might be ambiguous if multiple people send it.
						   Better to wrap it. */

						char *wrapped = malloc(len + 256);
						if (wrapped) {
							char esc_name[384];
							lws_json_purify(esc_name, p->name, sizeof(esc_name), NULL);

							int tlen = lws_snprintf(wrapped, len + 256 + sizeof(esc_name),
									"{\"type\":\"remote_capabilities\",\"target\":\"%s\",\"payload\":%.*s}",
									esc_name, (int)len, (const char *)in);

							struct broadcast_ctx bctx = { 0 };
							bctx.room = p->room;
							bctx.text = wrapped;
							bctx.len = (size_t)tlen;
							bctx.require_joined = 1; /* Only joined users need to know */
							bctx.exclude = p; /* Don't echo to sender */

							lws_dll2_foreach_safe(&p->room->participants, &bctx, broadcast_text_iter);
							free(wrapped);
						}

					} else if ((al >= 12 && !strncmp(v, "\"request_caps\"", 12)) ||
							(al >= 12 && !strncmp(v, "request_caps", 12))) {
						/* Note: fixed length check for "request_caps" to 12 */

						/* {"type":"request_caps","target":"<name>"} */
						lwsl_notice("%s: Received request_caps from '%s'\n", __func__, p->name);

						const char *tgt = lws_json_simple_find((const char *)in, len, "\"target\":", &al);
						if (tgt) {
							char target_name[64];
							size_t nl = al;
							if (*tgt == '\"') { tgt++; nl -= 2; }
							lws_strnncpy(target_name, tgt, sizeof(target_name), nl);

							/* Find target */
							lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&p->room->participants)) {
								struct participant *tp = lws_container_of(d, struct participant, list);
								if (!strcmp(tp->name, target_name) && tp->capabilities) {
									/* Send back wrapped caps */
									size_t msg_len = strlen(tp->capabilities) + 256 + (strlen(tp->name) * 6);
									char *resp = malloc(msg_len);
									if (resp) {
										char esc_name[384];
										lws_json_purify(esc_name, tp->name, sizeof(esc_name), NULL);

										lws_snprintf(resp, msg_len,
												"{\"type\":\"remote_capabilities\",\"target\":\"%s\",\"payload\":%s}",
												esc_name, tp->capabilities);
										we_ops->send_text(p->pss, resp, strlen(resp));
										free(resp);
									}
									break;
								}
							} lws_end_foreach_dll(d);
						}



					} else if ((al >= 6 && !strncmp(v, "\"chat\"", 6)) ||
							(al >= 4 && !strncmp(v, "chat", 4))) {
						/* {"type":"chat","text":"..."} */
						const char *txt = lws_json_simple_find((const char *)in, len, "\"text\":", &al);
						if (txt && al > 0) {
							struct chat_message *cm;
							size_t txt_len = al;
							char *txt_dup;

							if (*txt == '\"') { txt++; txt_len -= 2; }

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
							if (p->room->chat_history.count > 20) {
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
						broadcast_client_list(p->room, NULL);
					}

					if (p->capabilities)
						free(p->capabilities);

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
	{"lws-webrtc-mixer", callback_mixer, sizeof(struct pss_webrtc), 0, 0, NULL, 0},
};

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
