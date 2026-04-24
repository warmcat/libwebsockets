#include <libwebsockets.h>
#include <pthread.h>

#include <string.h>
#include <stdlib.h>


#include "mixer-media.h"

static gboolean
bus_call(GstBus *bus, GstMessage *msg, gpointer data)
{
	struct mixer_room *r = (struct mixer_room *)data;
	switch (GST_MESSAGE_TYPE(msg)) {
	case GST_MESSAGE_ERROR: {
		GError *err;
		gchar *debug;
		gst_message_parse_error(msg, &err, &debug);
		lwsl_err("GStreamer Error (room %s) from %s: %s\n", r->name, GST_MESSAGE_SRC_NAME(msg), err->message);
		if (debug) lwsl_err("Debug info: %s\n", debug);
		g_error_free(err);
		g_free(debug);
		break;
	}
	case GST_MESSAGE_WARNING: {
		GError *err;
		gchar *debug;
		gst_message_parse_warning(msg, &err, &debug);
		lwsl_warn("GStreamer Warning (room %s) from %s: %s\n", r->name, GST_MESSAGE_SRC_NAME(msg), err->message);
		if (debug) lwsl_warn("Debug info: %s\n", debug);
		g_error_free(err);
		g_free(debug);
		break;
	}
	case GST_MESSAGE_EOS:
		lwsl_notice("GStreamer EOS (room %s)\n", r->name);
		break;
	case GST_MESSAGE_QOS: {
		GstClockTime timestamp, duration, jitter;
		gboolean live;
		guint64 processed, dropped;
		gst_message_parse_qos(msg, &live, &timestamp, &duration, &jitter, &jitter);
		gst_message_parse_qos_stats(msg, NULL, &processed, &dropped);

		const gchar *src_name = GST_MESSAGE_SRC_NAME(msg);
		struct mixer_media_session *s_qos = NULL;
		const char *us = strchr(src_name, '_');
		if (us) {
			sscanf(us + 1, "%p", &s_qos);
		}
		if (s_qos) {
			s_qos->gst_qos_drops += (uint32_t)dropped;
		}

		lwsl_notice("GStreamer QoS (room %s) from %s: processed %llu, dropped %llu\n",
				r->name, src_name, (long long unsigned)processed, (long long unsigned)dropped);
		break;
	}
	case GST_MESSAGE_STATE_CHANGED: {
		GstState old_state, new_state, pending_state;
		gst_message_parse_state_changed(msg, &old_state, &new_state, &pending_state);
		if (GST_MESSAGE_SRC(msg) == GST_OBJECT(r->pipeline)) {
			lwsl_notice("Pipeline %s state changed from %s to %s\n",
					r->name, gst_element_state_get_name(old_state),
					gst_element_state_get_name(new_state));
		}
		break;
	}
	default:
		break;
	}
	return TRUE;
}

static GstPadProbeReturn
on_decodebin_buffer_probe(GstPad *pad, GstPadProbeInfo *info, gpointer data)
{
	struct mixer_media_session *s = (struct mixer_media_session *)data;
	GstBuffer *buffer = GST_PAD_PROBE_INFO_BUFFER(info);
	lwsl_debug("decoder output buffer for session %p: PTS %llu, size %zu\n",
			s, (unsigned long long)GST_BUFFER_PTS(buffer), gst_buffer_get_size(buffer));
	return GST_PAD_PROBE_OK;
}

static GstPadProbeReturn
on_compositor_src_buffer_probe(GstPad *pad, GstPadProbeInfo *info, gpointer data)
{
	GstBuffer *buffer = GST_PAD_PROBE_INFO_BUFFER(info);
	static int dbg_comp = 0;
	if (dbg_comp++ % 50 == 0) {
		lwsl_notice("PROBE COMPOSITOR SRC: PTS %llu ms\n",
			(unsigned long long)(GST_BUFFER_PTS(buffer) / 1000000));
	}
	return GST_PAD_PROBE_OK;
}

static GstPadProbeReturn
on_appsrc_buffer_probe(GstPad *pad, GstPadProbeInfo *info, gpointer data)
{
	GstBuffer *buffer = GST_PAD_PROBE_INFO_BUFFER(info);
	static int dbg_appsrc = 0;
	if (dbg_appsrc++ % 50 == 0) {
		lwsl_notice("PROBE APPSRC SRC: PTS %llu ms\n",
			(unsigned long long)(GST_BUFFER_PTS(buffer) / 1000000));
	}
	return GST_PAD_PROBE_OK;
}

/* Session Lifecycle */

struct mixer_media_session *
mixer_media_session_create(struct vhd_mixer *vhd, void *parent)
{
	struct mixer_media_session *s = malloc(sizeof(*s));
	if (!s) return NULL;
	memset(s, 0, sizeof(*s));

	s->ref_count = 1;
	s->parent_p = parent;
	lws_mutex_init(s->mutex);

	/* Create Input Ring (LWS -> Worker) */
	/* Buffer 2048 messages? */
	s->ring_input = lws_ring_create(sizeof(struct mixer_msg), 2048, NULL);
	if (!s->ring_input) {
		free(s);
		return NULL;
	}

	s->ring_input_buffer = malloc(sizeof(struct mixer_msg) * 2048);
	if (!s->ring_input_buffer) {
		lws_ring_destroy(s->ring_input);
		free(s);
		return NULL;
	}

	/* Initialize Opus Codecs */
	int err;
	s->decoder = opus_decoder_create(AUDIO_RATE, AUDIO_CHANNELS, &err);
	if (err != OPUS_OK) lwsl_err("%s: Opus decoder create failed: %d\n", __func__, err);

	s->encoder = opus_encoder_create(AUDIO_RATE, AUDIO_CHANNELS, OPUS_APPLICATION_VOIP, &err);
	if (err != OPUS_OK) {
		lwsl_err("%s: Opus encoder create failed: %d\n", __func__, err);
	} else {
		opus_encoder_ctl(s->encoder, OPUS_SET_BITRATE(20000));
		opus_encoder_ctl(s->encoder, OPUS_SET_VBR(0)); /* CBR for maximum compatibility */
		opus_encoder_ctl(s->encoder, OPUS_SET_COMPLEXITY(10));
		opus_encoder_ctl(s->encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
		opus_encoder_ctl(s->encoder, OPUS_SET_INBAND_FEC(0));
	}

	/* Initialize Audio Jitter Buffer */
	size_t elem_count = 100 * AUDIO_SAMPLES_PER_FRAME; /* 2000ms buffer */
	s->ring_buffer = malloc(elem_count * sizeof(int16_t));
	if (!s->ring_buffer) {
		lwsl_err("%s: OOM ring buffer\n", __func__);
		free(s->ring_input_buffer);
		lws_ring_destroy(s->ring_input);
		free(s);
		return NULL;
	}
	s->ring_pcm = lws_ring_create(sizeof(int16_t), elem_count, NULL);
	if (!s->ring_pcm) {
		free(s->ring_buffer);
		free(s->ring_input_buffer);
		lws_ring_destroy(s->ring_input);
		free(s);
		return NULL;
	}
	s->ring_tail = 0;
	s->ring_pcm_tail = 0;

	return s;
}

void
mixer_media_session_ref(struct mixer_media_session *s)
{
	lws_mutex_lock(s->mutex);
	s->ref_count++;
	lws_mutex_unlock(s->mutex);
}

void
mixer_media_session_destroy(struct mixer_media_session *s)
{
	if (!s) return;

	if (s->media && we_ops && we_ops->media_unref) {
		we_ops->media_unref(&s->media);
	}

    /* Resources */
	if (s->ring_pcm) lws_ring_destroy(s->ring_pcm);
	if (s->ring_buffer) free(s->ring_buffer);

	if (s->decoder) opus_decoder_destroy(s->decoder);
	if (s->encoder) opus_encoder_destroy(s->encoder);

	if (s->decoder) opus_decoder_destroy(s->decoder);
	if (s->encoder) opus_encoder_destroy(s->encoder);

	struct participant *pp = (struct participant *)s->parent_p;
	if (s->compositor_pad) {
		if (pp && pp->room && pp->room->compositor) {
			gst_element_release_request_pad(pp->room->compositor, s->compositor_pad);
		}
		gst_object_unref(s->compositor_pad);
		s->compositor_pad = NULL;
	}

	if (pp && pp->room && pp->room->pipeline) {
		if (s->decodebin) {
			gst_element_set_state(s->decodebin, GST_STATE_NULL);
			gst_bin_remove(GST_BIN(pp->room->pipeline), s->decodebin);
		}
		if (s->appsrc) {
			gst_element_set_state(s->appsrc, GST_STATE_NULL);
			gst_bin_remove(GST_BIN(pp->room->pipeline), s->appsrc);
		}
	} else {
		if (s->decodebin) {
			gst_element_set_state(s->decodebin, GST_STATE_NULL);
			gst_object_unref(s->decodebin);
		}
		if (s->appsrc) {
			gst_element_set_state(s->appsrc, GST_STATE_NULL);
			gst_object_unref(s->appsrc);
		}
	}
	s->decodebin = NULL;
	s->appsrc = NULL;

    /* Queues */
    lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&s->video_queue)) {
        struct video_queue_item *v = lws_container_of(d, struct video_queue_item, list);
        lws_dll2_remove(d);
        free(v->buf); free(v);
    } lws_end_foreach_dll_safe(d, d1);

    lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&s->rtp_queue)) {
        struct rtp_queue_item *r = lws_container_of(d, struct rtp_queue_item, list);
        lws_dll2_remove(d);
        free(r->buf); free(r);
    } lws_end_foreach_dll_safe(d, d1);

	if (s->video_buf) free(s->video_buf);
	if (s->obu_buf) free(s->obu_buf);

	if (s->ring_input) lws_ring_destroy(s->ring_input);

	lws_mutex_destroy(s->mutex);
	free(s);
}

void
mixer_media_session_unref(struct mixer_media_session *s)
{
	lws_mutex_lock(s->mutex);
	s->ref_count--;
	int zero = (s->ref_count == 0);
	lws_mutex_unlock(s->mutex);

	if (zero) {
        /* Remove from global session list if still attached */
        if (!lws_dll2_is_detached(&s->list)) {
             lws_dll2_remove(&s->list);
        }
        mixer_media_session_destroy(s);
    }
}

/* Worker Private Structures */
/* worker_room definition removed, using mixer_room */

struct compose_data {
    struct mixer_room *room;
    int x_off;
    int y_off;
};

struct codec_counts {
    struct mixer_room *room;
    int av1;
    int h264;
    int vp8;
};



/* Codec counts struct end */

/* worker_get_or_create_room removed */
/* Re-implementing with correct structure */

static void
process_control_message(struct vhd_mixer *vhd, struct mixer_msg *msg)
{
	struct mixer_media_session *s = msg->session;

	if (msg->type == MSG_ADD_SESSION) {
		/* room_name is in payload */

		/* Let's simply add to vhd->sessions. */
		lws_dll2_add_tail(&s->list, &vhd->sessions);

		/* Copy room name from payload */
		if (msg->payload) {
			lws_strncpy(s->room_name, (const char *)msg->payload, sizeof(s->room_name));
			free(msg->payload);
		}

		return;
	}

	if (msg->type == MSG_REMOVE_SESSION) {
		/* Find the room to release the compositor pad */
		struct mixer_room *r = NULL;
		lws_start_foreach_dll(struct lws_dll2 *, d_r, lws_dll2_get_head(&vhd->rooms)) {
			struct mixer_room *tr = lws_container_of(d_r, struct mixer_room, list);
			if (!strcmp(tr->name, s->room_name)) {
				r = tr;
				break;
			}
		} lws_end_foreach_dll(d_r);

		if (s->compositor_pad && r && r->compositor) {
			lwsl_notice("Releasing compositor pad %s for session %p in room %s\n",
					gst_pad_get_name(s->compositor_pad), s, s->room_name);
			gst_element_release_request_pad(r->compositor, s->compositor_pad);
			gst_object_unref(s->compositor_pad);
			s->compositor_pad = NULL;
		}

		if (!lws_dll2_is_detached(&s->list)) {
			lws_dll2_remove(&s->list);
		}

		if (r) {
			int active_sessions = 0;
			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
				struct mixer_media_session *ts = lws_container_of(d, struct mixer_media_session, list);
				if (!strcmp(ts->room_name, r->name))
					active_sessions++;
			} lws_end_foreach_dll(d);

			if (active_sessions == 0) {
				lwsl_notice("Room %s is empty, resetting pipeline to READY to prevent catch-up bursts\n", r->name);
				/*
				 * We must use READY instead of PAUSED.
				 * PAUSED preserves the running time. When a new user joins, their injected PTS
				 * will reflect the old running time, but the compositor's output will have stalled,
				 * causing a massive gap that it attempts to catch up with fast-forward frames.
				 * READY completely resets the pipeline running time to 0 for the next session.
				 */
				gst_element_set_state(r->pipeline, GST_STATE_READY);
			}
		}

		mixer_media_session_unref(s);
		return;
	}

	if (msg->type == MSG_UNREF_SESSION) {
		mixer_media_session_unref(s);
		return;
	}
}

static void
append_av1_obu(struct mixer_media_session *s, const uint8_t *data, size_t len)
{
	if (len < 1) return;

	static int dbg_obu = 0;
	if (dbg_obu++ < 25) {
		char hexb[256] = {0};
		for(int h=0; h<(int)(len<48?len:48); h++) snprintf(hexb+strlen(hexb), sizeof(hexb)-strlen(hexb), "%02x ", data[h]);
		lwsl_notice("APPEND OBU (len %zu): %s\n", len, hexb);
	}

	uint8_t hdr = data[0];
	int has_ext = (hdr & 0x04) != 0;
	int has_size = (hdr & 0x02) != 0;

	size_t hdr_len = 1 + (has_ext ? 1 : 0);
	if (len < hdr_len) return;

	size_t payload_len = len - hdr_len;
	size_t off = hdr_len;

	/* If the OBU has an internal size field, we MUST strip it out for Annex B. */
	if (has_size) {
		size_t leb_len = 0;
		size_t tmp = 0;
		for (size_t j = 0; j < 8 && off + j < len; j++) {
			uint8_t byte = data[off + j];
			tmp |= ((size_t)(byte & 0x7F)) << (j * 7);
			if (!(byte & 0x80)) { leb_len = j + 1; break; }
		}
		if (!leb_len) {
			lwsl_notice("%s: Invalid internal LEB128 size (len=%zu, off=%zu). Hex:\n", __func__, len, off);
			char hexb[128] = {0};
			for(int h=0; h<(int)(len<24?len:24); h++) snprintf(hexb+strlen(hexb), sizeof(hexb)-strlen(hexb), "%02x ", data[h]);
			lwsl_notice("  %s\n", hexb);
			/* Fallback: assume the rest of the payload IS the size if leb failed. */
			payload_len = len - off;
		} else {
			off += leb_len;
			payload_len = len - off;
		}
	}

	/*
	 * In "Section 5" (Low Overhead Bitstream Format) which libdav1d expects
	 * from FFmpeg out-of-band frames:
	 * We MUST set obu_has_size_field = 1.
	 * Then we write: Header -> Ext -> LEB128 Payload Size -> Payload.
	 */
	uint8_t leb[8];
	size_t leb_len = 0;
	size_t tmp = payload_len; /* Size of JUST the payload */
	do {
		uint8_t byte = tmp & 0x7F;
		tmp >>= 7;
		if (tmp != 0) byte |= 0x80;
		leb[leb_len++] = byte;
	} while (tmp != 0);

	size_t needed = s->video_len + hdr_len + leb_len + payload_len + 4;
	if (s->video_alloc < needed) {
		s->video_alloc = needed + 4096;
		s->video_buf = realloc(s->video_buf, s->video_alloc);
	}

	if (s->video_buf) {
		if (s->video_len == 0 && ((hdr & 0x78) >> 3) != 2) {
			/* Prepend Temporal Delimiter OBU (Type 2) with size_field=1, length=0 */
			s->video_buf[s->video_len++] = 0x12; /* 0001 0010 */
			s->video_buf[s->video_len++] = 0x00;
		}

		/* 1. Write OBU Header with `obu_has_size_field` FORCE set */
		s->video_buf[s->video_len++] = hdr | 0x02;

		/* 2. Write extension header if present */
		if (has_ext) {
			s->video_buf[s->video_len++] = data[1];
		}

		/* 3. Append LEB128 Payload Length */
		memcpy(s->video_buf + s->video_len, leb, leb_len);
		s->video_len += leb_len;

		/* 4. Write Payload */
		memcpy(s->video_buf + s->video_len, data + off, payload_len);
		s->video_len += payload_len;
	}
}

static void
process_session_media(struct mixer_media_session *s)
{
	struct mixer_msg *msg_ptr, msg_copy, *msg = &msg_copy;
	size_t waiting;

	while (1) {
		lws_mutex_lock(s->mutex);
		waiting = lws_ring_get_count_waiting_elements(s->ring_input, &s->ring_tail);
		if (waiting == 0) {
			lws_mutex_unlock(s->mutex);
			break;
		}

		msg_ptr = (struct mixer_msg *)lws_ring_get_element(s->ring_input, &s->ring_tail);
		if (!msg_ptr) {
			lws_mutex_unlock(s->mutex);
			break;
		}
		msg_copy = *msg_ptr;
		lws_ring_consume(s->ring_input, &s->ring_tail, NULL, 1);
		lws_ring_update_oldest_tail(s->ring_input, s->ring_tail);
		lws_mutex_unlock(s->mutex);

		if (msg->type == MSG_AUDIO_FRAME) {
			if (s->decoder && msg->payload) {
				int ret = opus_decode(s->decoder, (const unsigned char *)msg->payload, (opus_int32)msg->len,
						s->pcm_in, AUDIO_SAMPLES_PER_FRAME, 0);
				if (ret > 0) {
					/* Push to Jitter Ring */
					if (s->ring_pcm) {
						size_t free_space = lws_ring_get_count_free_elements(s->ring_pcm);
						if (free_space < (size_t)ret) {
							size_t drop = (size_t)ret - free_space;
							lws_ring_consume(s->ring_pcm, &s->ring_pcm_tail, NULL, drop);
							lws_ring_update_oldest_tail(s->ring_pcm, s->ring_pcm_tail);
							static int dbg_jitter = 0;
							if (dbg_jitter++ % 50 == 0)
								lwsl_warn("%s: Dropped %zu PCM samples (Jitter full)\n", __func__, drop);
						}
						if (lws_ring_insert(s->ring_pcm, s->pcm_in, (size_t)ret) != (size_t)ret) {
							lwsl_err("%s: Failed to insert PCM samples into ring\n", __func__);
						}
#if 0
						static int dbg_dec = 0;
						if (dbg_dec++ % 50 == 0)
							lwsl_notice("%s: opus_decode produced %d samples (waiting %zu)\n",
									__func__, ret, lws_ring_get_count_waiting_elements(s->ring_pcm, &s->ring_pcm_tail));
#endif
					}
					s->audio_seen = 1;
				} else if (ret < 0) {
					lwsl_warn("%s: opus_decode failed! ret = %d (len %zu)\n", __func__, ret, msg->len);
				}
			} else {
				lwsl_warn("%s: No Opus Decoder initialized!\n", __func__);
			}
		} else if (msg->type == MSG_VIDEO_FRAME) {
			/* Check for missing packets / lost marker using timestamps */
			if (msg->timestamp != s->video_timestamp) {
				if (s->video_len > 0) {
					lwsl_warn("%s: Dropping incomplete video frame (timestamp changed %u -> %u)\n", 
							__func__, s->video_timestamp, msg->timestamp);
					s->video_len = 0;
					s->obu_len = 0;
				}
				s->video_timestamp = msg->timestamp;
			}

			/* Handle Video logic */

			if (!s->appsrc && s->parent_p) {
				s->last_dec_codec = msg->codec;
				init_participant_media((struct participant *)s->parent_p, msg->codec);
			}

			if (s->appsrc) {
				/*
				 * lws_transcode_decode returns:
				 * 0: Frame decoded
				 * 1: Need more data / no frame produced yet
				 * <0: Error
				 */

				uint8_t *in_data = ((uint8_t *)msg->payload);
				size_t in_len = msg->len;
				int ready_to_decode = 1;

				if (msg->codec == LWS_CODEC_H264 && in_data && in_len > 0) {
					ready_to_decode = 0;
					uint8_t header = in_data[0];
					uint8_t type = header & 0x1F;
					const uint8_t annexb_start[4] = { 0, 0, 0, 1 };

					if (type >= 1 && type <= 23) {
						/* Single NAL Unit */
						size_t needed = s->video_len + in_len + 4;
						if (s->video_alloc < needed) {
							s->video_buf = realloc(s->video_buf, needed + 1024);
							s->video_alloc = needed + 1024;
						}
						if (s->video_buf) {
							memcpy(s->video_buf + s->video_len, annexb_start, 4);
							s->video_len += 4;
							memcpy(s->video_buf + s->video_len, in_data, in_len);
							s->video_len += in_len;
						}
					} else if (type == 24) {
						/* STAP-A: Single-Time Aggregation Packet */
						size_t off = 1; /* Skip STAP-A header */
						while (off + 2 <= in_len) {
							uint16_t nal_size = (uint16_t)((in_data[off] << 8) | in_data[off+1]);
							off += 2;
							if (nal_size == 0) {
								lwsl_err("%s: H264 Parse Error: 0-length NAL in STAP-A detected, breaking loop\n", __func__);
								break;
							}
							if (off + nal_size > in_len) break;
							size_t needed = s->video_len + nal_size + 4;
							if (s->video_alloc < needed) {
								s->video_buf = realloc(s->video_buf, needed + 1024);
								s->video_alloc = needed + 1024;
							}
							if (s->video_buf) {
								memcpy(s->video_buf + s->video_len, annexb_start, 4);
								s->video_len += 4;
								memcpy(s->video_buf + s->video_len, in_data + off, nal_size);
								s->video_len += nal_size;
								static int dbg_stap = 0;
								if (dbg_stap++ % 100 == 0) lwsl_notice("STAP-A: appended %u bytes\n", nal_size);
							}
							off += nal_size;
						}
					} else if (type == 28) {
						/* FU-A: Fragmentation Unit */
						if (in_len >= 2) {
							uint8_t fu_header = in_data[1];
							uint8_t S = (fu_header & 0x80) >> 7;
							// uint8_t E = (fu_header & 0x40) >> 6;
							uint8_t nal_type = fu_header & 0x1F;
							size_t payload_len = in_len - 2;
							const uint8_t *payload = in_data + 2;

							if (S) {
								/* Start of fragment */
								s->fu_a_active = 1;
								size_t needed = s->video_len + payload_len + 5;
								if (s->video_alloc < needed) {
									s->video_buf = realloc(s->video_buf, needed + 4096);
									s->video_alloc = needed + 4096;
								}
								if (s->video_buf) {
									memcpy(s->video_buf + s->video_len, annexb_start, 4);
									s->video_len += 4;
									/* Reconstruct NAL header */
									s->video_buf[s->video_len] = (header & 0xE0) | nal_type;
									s->video_len += 1;
									memcpy(s->video_buf + s->video_len, payload, payload_len);
									s->video_len += payload_len;

									// static int dbg_fua1 = 0;
									// if (dbg_fua1++ % 500 == 0)
									// 	lwsl_notice("FU-A: Start fragment, NAL type %u, len %zu\n", nal_type, payload_len);
								}
							} else if (s->video_buf && s->video_len > 0 && s->fu_a_active) {
								/* Middle or end of fragment */
								size_t needed = s->video_len + payload_len;
								if (s->video_alloc < needed) {
									s->video_buf = realloc(s->video_buf, needed + 4096);
									s->video_alloc = needed + 4096;
								}
								if (s->video_buf) {
									memcpy(s->video_buf + s->video_len, payload, payload_len);
									s->video_len += payload_len;

									// static int dbg_fua2 = 0;
									// if (dbg_fua2++ % 2000 == 0)
									// 	lwsl_notice("FU-A: Cont fragment, len %zu\n", payload_len);
								}
								/* We don't decode on 'E', we decode on 'marker' */
							}
						}
					}

					if (msg->marker && s->video_buf && s->video_len > 0) {
						s->fu_a_active = 0; /* Frame boundary hit, reset FU-A state */
						in_data = s->video_buf;
						in_len = s->video_len;
						ready_to_decode = 1;

					//	static int dbg_marker = 0;
					//	if (dbg_marker++ % 50 == 0)
					//		lwsl_notice("H264 Marker Received! Feeding Frame to decoder (len %zu)\n", in_len);
					}
				} else if (msg->codec == LWS_CODEC_AV1 && in_data && in_len > 1) {
					ready_to_decode = 0; /* VERY IMPORTANT! Do not decode until marker=1 */
					/*
					   static int dbg_hex = 0;
					   if (dbg_hex++ < 25) {
					   char hexbuf[128] = {0};
					   int max = in_len > 24 ? 24 : (int)in_len;
					   for(int h=0; h<max; h++) sprintf(hexbuf + strlen(hexbuf), "%02x ", in_data[h]);
					   lwsl_notice("AV1 RAW IN (len %zu, marker %d): %s\n", in_len, msg->marker, hexbuf);
					   }
					   */

					uint8_t aggr_header = in_data[0];
					uint8_t Z = (aggr_header >> 7) & 1;
					uint8_t Y = (aggr_header >> 6) & 1;
					uint8_t W = (aggr_header >> 4) & 3;

					static int dbg_aggr = 0;
					if (dbg_aggr++ < 50) {
						lwsl_notice("AGGR HDR: Z=%d Y=%d W=%d (in_len=%zu, marker=%d)\n", Z, Y, W, in_len, msg->marker);
					}

					size_t off = 1; /* Skip aggregation header */

					/* If Z == 0, this packet starts with a fresh OBU. Discard any incomplete fragments. */
					if (Z == 0) {
						s->obu_len = 0;
					}

					/* Track if we have a valid fragment chain */
					int drop_fragment = (Z == 1 && s->obu_len == 0);

					/* Loop over payload to extract OBUs based on W */
					/* Loop over payload to extract OBUs based on W */
					int elem_idx = 0;
					while (off < in_len) {
						size_t obu_size = 0, leb_len = 0;
						int has_size_field = 0;

						if (W == 0) {
							/* If W=0, EVERY element has an explicit size field.
							 * We parse until we hit the end of the packet. */
							has_size_field = 1;
						} else {
							/* If W=1, 2, or 3, it counts exactly how many elements exist.
							 * EVERY element EXCEPT the last one has a size field.
							 * The last one spans the rest of the packet. */
							has_size_field = (elem_idx == (W - 1)) ? 0 : 1;
						}

						if (has_size_field) {
							size_t tmp = 0;
							for (size_t j = 0; j < 8 && off + j < in_len; j++) {
								uint8_t byte = in_data[off + j];
								tmp |= ((size_t)(byte & 0x7F)) << (j * 7);
								if (!(byte & 0x80)) {
									leb_len = j + 1;
									obu_size = tmp;
									break;
								}
							}

							/* Overran packet or invalid LEB128 */
							if (!leb_len || off + leb_len + obu_size > in_len) {
								/* If W=1, W=2, W=3, it might just be the last element which omits the size field implicitly */
								has_size_field = 0;
							}
						}

						/* If we determined there is no size field (either by W rule or fallback from overrun) */
						if (!has_size_field) {
							leb_len = 0;
							obu_size = in_len - off; /* Consume remainder of packet */
						}

						off += leb_len;

						int is_first_elem = (elem_idx == 0);
						int is_last_elem_in_packet = (off + obu_size == in_len);

						if (is_first_elem && Z == 1) {
							/* Continuation fragment from a PREVIOUS packet */
							if (!drop_fragment && s->obu_buf) {
								if (s->obu_len + obu_size > s->obu_alloc) {
									s->obu_alloc = s->obu_len + obu_size + 4096;
									s->obu_buf = realloc(s->obu_buf, s->obu_alloc);
								}
								if (s->obu_buf) {
									memcpy(s->obu_buf + s->obu_len, in_data + off, obu_size);
									s->obu_len += obu_size;

									/* Complete if not continuing into NEXT packet */
									if (!(is_last_elem_in_packet && Y == 1)) {
										append_av1_obu(s, s->obu_buf, s->obu_len);
										s->obu_len = 0;
									}
								}
							}
						} else {
							/* Brand new element starting in THIS packet */
							if (is_last_elem_in_packet && Y == 1) {
								/* Begins here, continues into NEXT packet */
								if (dbg_aggr < 50) lwsl_notice("  -> Frag START: idx=%d, size=%zu\n", elem_idx, obu_size);
								s->obu_len = 0;
								if (obu_size > s->obu_alloc) {
									s->obu_alloc = obu_size + 4096;
									s->obu_buf = realloc(s->obu_buf, s->obu_alloc);
								}
								if (s->obu_buf && obu_size > 0) {
									memcpy(s->obu_buf, in_data + off, obu_size);
									s->obu_len = obu_size;
								}
							} else {
								/* Complete within this packet */
								if (dbg_aggr < 50) lwsl_notice("  -> Frag COMPLETE: idx=%d, size=%zu\n", elem_idx, obu_size);
								append_av1_obu(s, in_data + off, obu_size);
							}
						}

						off += obu_size;
						if (leb_len == 0 && obu_size == 0) {
							lwsl_err("%s: AV1 Parse Error: 0-length OBU detected, breaking loop\n", __func__);
							break;
						}
						elem_idx++;
					}

					if (msg->marker) {
						static int dbg_marker = 0;
						if (dbg_marker++ % 50 == 0)
							lwsl_notice("%s: Received RTP marker for room %s, frame len %zu\n", __func__, s->room_name, s->video_len);
						if (s->video_buf && s->video_len > 0) {
							in_data = s->video_buf;
							in_len = s->video_len;
							ready_to_decode = 1;
						}
					}
				}

				if (ready_to_decode && s->appsrc) {
					GstBuffer *buffer = gst_buffer_new_allocate(NULL, in_len, NULL);
					gst_buffer_fill(buffer, 0, in_data, in_len);

					/*
					 * To prevent h264parse from merging identical timestamps during CPU
					 * spikes, we manually generate the PTS using the pipeline clock
					 * but strictly enforce a monotonic +1ms offset if they arrive in
					 * the exact same millisecond.
					 */
					GstClock *clock = gst_element_get_clock(s->appsrc);
					GstClockTime pts = GST_CLOCK_TIME_NONE;
					if (clock) {
						struct participant *pp = (struct participant *)s->parent_p;
						if (pp && pp->room && pp->room->pipeline) {
							pts = gst_clock_get_time(clock) - gst_element_get_base_time(pp->room->pipeline);
						} else {
							pts = gst_clock_get_time(clock) - gst_element_get_base_time(s->appsrc);
						}

						static int dbg_in = 0;
						if (dbg_in++ % 50 == 0)
							lwsl_notice("INJECT: pts %llu ms, clock %llu ms, base %llu ms\n",
								(unsigned long long)(pts / 1000000),
								(unsigned long long)(gst_clock_get_time(clock) / 1000000),
								(unsigned long long)(gst_element_get_base_time(pp && pp->room ? pp->room->pipeline : s->appsrc) / 1000000));

						gst_object_unref(clock);
					}

					if (pts != GST_CLOCK_TIME_NONE) {
						if (s->last_pts != GST_CLOCK_TIME_NONE && pts <= s->last_pts) {
							pts = s->last_pts + 1000000ull; /* +1 millisecond */
						}
						s->last_pts = pts;
					}

					GST_BUFFER_PTS(buffer) = pts;
					GST_BUFFER_DTS(buffer) = GST_CLOCK_TIME_NONE;

					GstFlowReturn ret = gst_app_src_push_buffer(GST_APP_SRC(s->appsrc), buffer);
					if (ret != GST_FLOW_OK) {
						lwsl_err("%s: Failed to push buffer to appsrc (ret %d)\n", __func__, ret);
					} else {
						s->decoded_frames++;
						s->processed_frames_count++;
					}

					/* Reset buffer for next frame */
					s->video_len = 0;
					s->obu_len = 0;
				}

			}


		}

		if (msg->payload) {
			free(msg->payload);
			msg->payload = NULL;
		}
	}
}

static int
process_room_mix(struct vhd_mixer *vhd, struct mixer_room *r, lws_usec_t deadline)
{
	int h264_dropped = 0;

	/* 1. Poll GStreamer Bus for errors/status */
	if (r->pipeline) {
		GstBus *bus = gst_element_get_bus(r->pipeline);
		GstMessage *msg;
		while ((msg = gst_bus_pop(bus))) {
			bus_call(bus, msg, r);
			gst_message_unref(msg);
		}
		gst_object_unref(bus);
	}

	/* 2. Sum Audio */
	memset(r->mixed_pcm, 0, sizeof(r->mixed_pcm));

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
		struct mixer_media_session *s = lws_container_of(d, struct mixer_media_session, list);
		if (strcmp(s->room_name, r->name)) goto skip_decode;

		/* Jitter Buffer Consumer Logic */
		lws_mutex_lock(s->mutex); /* Protected access to ring_pcm */
		if (s->ring_pcm) {
			size_t waiting = lws_ring_get_count_waiting_elements(s->ring_pcm, &s->ring_pcm_tail);

			/* Catch up if we are drifting and buffering too much (prevent multi-second delay) */
			if (waiting >= 50 * AUDIO_SAMPLES_PER_FRAME) { /* 1000ms delay */
				/* Drop down to 25 frames (500ms) to stay within reasonable latency */
				size_t drop_frames = (waiting / AUDIO_SAMPLES_PER_FRAME) - 25;
				size_t drop = drop_frames * AUDIO_SAMPLES_PER_FRAME;

				if (drop > 0) {
					lws_ring_consume(s->ring_pcm, &s->ring_pcm_tail, NULL, drop);
					lws_ring_update_oldest_tail(s->ring_pcm, s->ring_pcm_tail);
					static int dbg_drift = 0;
					if (dbg_drift++ % 50 == 0)
						lwsl_notice("%s: Audio DRIFT catch-up! Dropped %zu samples for %s\n", __func__, drop, s->room_name);
					waiting = lws_ring_get_count_waiting_elements(s->ring_pcm, &s->ring_pcm_tail);
				}
			}

			if (waiting >= AUDIO_SAMPLES_PER_FRAME) {
				int16_t pcm[AUDIO_SAMPLES_PER_FRAME];
				lws_ring_consume(s->ring_pcm, &s->ring_pcm_tail, pcm, AUDIO_SAMPLES_PER_FRAME);
				lws_ring_update_oldest_tail(s->ring_pcm, s->ring_pcm_tail);

				for (int i=0; i<AUDIO_SAMPLES_PER_FRAME; i++)
					r->mixed_pcm[i] += pcm[i];

				s->has_pcm = 1; /* Mark for mix-minus */
				memcpy(s->pcm_in, pcm, sizeof(pcm)); /* Reuse pcm_in for mix-minus subtraction */

				/* Calc Energy */
				lws_media_audio_calc_energy(&r->audio_info, pcm, AUDIO_SAMPLES_PER_FRAME, &s->audio_energy);

			} else {
				s->has_pcm = 0;
				s->audio_energy = 0;
				if (waiting > 0) {
					static int starvation = 0;
					if (starvation++ % 50 == 0)
						lwsl_notice("%s: Audio starvation - %zu samples waiting (< %d)\n",
								__func__, waiting, AUDIO_SAMPLES_PER_FRAME);
				}
			}
		} else {
			s->has_pcm = 0;
			s->audio_energy = 0;
		}
		lws_mutex_unlock(s->mutex);

skip_decode:
	} lws_end_foreach_dll(d);

	/* 2. Encode Audio (Mix-Minus) & Send */
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
		struct mixer_media_session *s = lws_container_of(d, struct mixer_media_session, list);
		if (strcmp(s->room_name, r->name)) goto skip_encode;

		if (s->encoder) {
			int16_t out_pcm[AUDIO_SAMPLES_PER_FRAME];

			for (int i=0; i<AUDIO_SAMPLES_PER_FRAME; i++) {
				int32_t val = r->mixed_pcm[i];
				if (s->has_pcm) val -= s->pcm_in[i]; /* Mix-Minus */
				out_pcm[i] = soft_clip(val);
			}

			unsigned char opus[512];
			/* Warning: We MUST use the soft-clipped out_pcm for encode */
			int ret = opus_encode(s->encoder, out_pcm, AUDIO_SAMPLES_PER_FRAME, opus, sizeof(opus));

			//static int audio_enc_log = 0;
			//if (audio_enc_log++ % 100 == 0 && s->has_pcm) {
			//	lwsl_notice("%s: Encoded Audio for %s (ret %d, input energy %u)\n",
			//				__func__, s->room_name, ret, (unsigned int)s->audio_energy);
			//}

			if (ret > 0) {
				if (s->media && we_ops && we_ops->send_audio) {
					we_ops->send_audio(s->media, opus, (size_t)ret, (uint32_t)(r->master_pts * 960));
				}
			}
		}

skip_encode:
	} lws_end_foreach_dll(d);

	/* 3. Video Compose & Encode */
	r->master_pts++;

	// static int dbg_room = 0;
	// if (dbg_room++ % 100 == 0)
	//	lwsl_notice("Room %s: master_pts %llu, sessions %u\n",
	//			r->name, (unsigned long long)r->master_pts, r->participants.count);

	if ((r->master_pts & 1) == 0) { /* 25fps */

		/* Broadcast previously encoded H264 frames */
		pthread_mutex_lock(&r->encode_mutex);
		while (lws_dll2_get_head(&r->h264_queue)) {
			struct mixer_encoded_frame *f = lws_container_of(lws_dll2_get_head(&r->h264_queue), struct mixer_encoded_frame, list);
			lws_dll2_remove(&f->list);
			pthread_mutex_unlock(&r->encode_mutex);

			uint32_t rtp_ts = f->rtp_ts ? f->rtp_ts : (uint32_t)((r->master_pts / 2) * 3600); // Fallback to master_pts if PTS missing

			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
				struct mixer_media_session *s = lws_container_of(d, struct mixer_media_session, list);
				if (strcmp(s->room_name, r->name)) goto next_tx_h264;
				lws_mutex_lock(s->mutex);
				int can_rx_h264 = s->can_rx_h264;
				lws_mutex_unlock(s->mutex);
				if (can_rx_h264) {
					if (s->media && we_ops && we_ops->send_video) {
						static int dbg_tx = 0;
						if (dbg_tx++ % 50 == 0)
							lwsl_debug("TX Video: room %s, len %zu, RTP TS %u (master_pts %llu)\n",
									r->name, f->len, rtp_ts, (unsigned long long)r->master_pts);
						we_ops->send_video(s->media, f->buf, f->len, LWS_CODEC_H264, rtp_ts);
					}
				}
next_tx_h264:;
			} lws_end_foreach_dll(d);

			free(f->buf);
			free(f);
			pthread_mutex_lock(&r->encode_mutex);
		}

		/* Broadcast previously encoded AV1 frames */
		while (lws_dll2_get_head(&r->av1_queue)) {
			struct mixer_encoded_frame *f = lws_container_of(lws_dll2_get_head(&r->av1_queue), struct mixer_encoded_frame, list);
			lws_dll2_remove(&f->list);
			pthread_mutex_unlock(&r->encode_mutex);

			uint32_t rtp_ts = f->rtp_ts ? f->rtp_ts : (uint32_t)((r->master_pts / 2) * 3600);

			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
				struct mixer_media_session *s = lws_container_of(d, struct mixer_media_session, list);
				if (strcmp(s->room_name, r->name)) goto next_tx_av1;
				lws_mutex_lock(s->mutex);
				int can_rx_av1 = s->can_rx_av1;
				lws_mutex_unlock(s->mutex);
				if (can_rx_av1) {
					if (s->media && we_ops && we_ops->send_video) {
						we_ops->send_video(s->media, f->buf, f->len, LWS_CODEC_AV1, rtp_ts);
					}
				}
next_tx_av1:;
			} lws_end_foreach_dll(d);

			free(f->buf);
			free(f);
			pthread_mutex_lock(&r->encode_mutex);
		}
		pthread_mutex_unlock(&r->encode_mutex);

		/* Apply Layout to GStreamer Compositor Pads */
		r->lm_ops->update(r, r->lm_ctx);
		int num_regions = 0;
		const struct lws_mixer_layout_region *regions = r->lm_ops->get_regions(r->lm_ctx, &num_regions);

		for (int i = 0; i < num_regions; i++) {
			const struct lws_mixer_layout_region *reg = &regions[i];
			struct mixer_media_session *s = reg->s;

			if (s->compositor_pad && s->decoded_frames > 0) {
				static int dbg_pad = 0;
				if (dbg_pad++ % 100 == 0)
					lwsl_notice("Setting pad %p: %dx%d @ %d,%d\n",
							s->compositor_pad, reg->w, reg->h, reg->x, reg->y);
				g_object_set(G_OBJECT(s->compositor_pad),
					"xpos", reg->x,
					"ypos", reg->y,
					"width", reg->w,
					"height", reg->h,
					NULL);
			}
		}
	}

	return h264_dropped;
}


void *
media_worker_thread(void *d)
{
	struct vhd_mixer *vhd = (struct vhd_mixer *)d;
	struct mixer_msg *msg;
	lws_usec_t next_frame_time;

	lwsl_user("%s: Worker Thread Started\n", __func__);
	next_frame_time = lws_now_usecs() + 20000;

	while (vhd->worker_running) {
		lws_usec_t now = lws_now_usecs();
		if (now < next_frame_time) {
			lws_usec_t diff = next_frame_time - now;
			if (diff > 500)
				usleep((useconds_t)diff);
			continue;
		}

		/* Catch up if way behind (e.g. debugger paused), jump to now to avoid massive bursts */
		if (now - next_frame_time > 100000) {
			lwsl_warn("%s: Worker lagging! Jumping %llu us\n", __func__, (unsigned long long)(now - next_frame_time));
			next_frame_time = now;
		}

		next_frame_time += 20000;

        /* 1. Process Control Messages (Add/Remove Sessions) */
        lws_mutex_lock(vhd->mutex_rx);
        while (lws_ring_get_count_waiting_elements(vhd->ring_rx, &vhd->ring_rx_tail) > 0) {
             msg = (struct mixer_msg *)lws_ring_get_element(vhd->ring_rx, &vhd->ring_rx_tail);
             if (!msg)
                 break;
             process_control_message(vhd, msg);
             lws_ring_consume(vhd->ring_rx, &vhd->ring_rx_tail, NULL, 1);
             lws_ring_update_oldest_tail(vhd->ring_rx, vhd->ring_rx_tail);
        }
        lws_mutex_unlock(vhd->mutex_rx);



        /* 2. Process Session Media (Decode) */
        lws_start_foreach_dll(struct lws_dll2 *, d_s, lws_dll2_get_head(&vhd->sessions)) {
             struct mixer_media_session *s = lws_container_of(d_s, struct mixer_media_session, list);
             process_session_media(s);
        } lws_end_foreach_dll(d_s);

        /* 3. Mix & Encode */
        lws_start_foreach_dll(struct lws_dll2 *, d_r, lws_dll2_get_head(&vhd->rooms)) {
            struct mixer_room *r = lws_container_of(d_r, struct mixer_room, list);
            int h264_dropped = process_room_mix(vhd, r, next_frame_time);

            /* Report CPU keeping up (true if finished within 20ms of deadline and encoder didn't drop frames) */
            lws_usec_t now_end = lws_now_usecs();
            lws_adapt_report(r->adapt_h264, (now_end < next_frame_time + 20000) && !h264_dropped, now_end);
        } lws_end_foreach_dll(d_r);
	}

	lwsl_user("%s: Worker Thread Exiting\n", __func__);
	return NULL;
}

/*
 * Cubic Soft Clipper
 * Maps [-32768, 32768] to [-32768, 32768] but compresses high amplitude smoothly.
 * Transition point: 20000 (approx -4dB)
 *
 * Polynomial Approximation for x > T:
 * f(x) = x - k(x-T)^3
 */
int16_t soft_clip(int32_t sample)
{
	if (sample > 20000) {
		if (sample >= 32767) return 32767;
		/* Compression Region: 20000 -> 32767 */
		/* Simple cubic approx or just a softer clamp */
		/* Let's use a simple rational function approximation for speed */
		/* y = T + (x-T) / (1 + ((x-T)/(Max-T))^2) ... too complex */
		/* Let's use x - (x^3)/3 normalized? Too slow. */
		/* Simple hard knee for now with slight roll-off? */
		/* Actually, simple tanh-like: */
		/* y = x < 20000 ? x : 20000 + (12767 * tanh((x-20000)/12767)) */
		/* Fast integer approximation: */
		int32_t over = sample - 20000;
		int32_t max_over = 12767;
		// parabolic roll-off: y = x - x^2 / 4*max
		// y = 20000 + over - (over*over) / (4*max_over)
		// This reaches slope 0 at max_over (32767 input).
		// 20000 + 12767 - (12767^2)/(4*12767) = 32767 - 3191 = 29576 max output. Safe!
		return (int16_t)(20000 + over - ((over * over) / (4 * max_over)));
	}
	if (sample < -20000) {
		if (sample <= -32768) return -32768;
		int32_t over = -(sample + 20000);
		int32_t max_over = 12767;
		return (int16_t)-(20000 + over - ((over * over) / (4 * max_over)));
	}
	return (int16_t)sample;
}

/* Moved above */

static GstFlowReturn
on_new_sample_h264(GstElement *sink, struct mixer_room *r)
{
	GstSample *sample;

	// lwsl_notice("on_new_sample_h264: Called for room %s\n", r->name);

	g_signal_emit_by_name(sink, "pull-sample", &sample);
	if (sample) {
		GstBuffer *buffer = gst_sample_get_buffer(sample);
		GstMapInfo info;
		if (gst_buffer_map(buffer, &info, GST_MAP_READ)) {
			struct mixer_encoded_frame *f = calloc(1, sizeof(*f));
			if (f) {
				f->buf = malloc(info.size);
				if (f->buf) {
					memcpy(f->buf, info.data, info.size);
					f->len = info.size;

					GstClockTime pts = GST_BUFFER_PTS(buffer);

					/* Drop massive catch-up bursts from compositor when a room is re-joined after being empty */
					int drop = 0;
					if (GST_CLOCK_TIME_IS_VALID(pts)) {
						f->rtp_ts = (uint32_t)(pts * 9 / 100000);
						GstClock *clock = gst_element_get_clock(sink);
						if (clock) {
							GstClockTime now = gst_clock_get_time(clock) - gst_element_get_base_time(sink);
							gst_object_unref(clock);
							if (now > pts + 1000000000ull) {
								drop = 1;
							}

							static int dbg_out = 0;
							if (dbg_out++ % 50 == 0 || drop) {
								lwsl_notice("EXTRACT: pts %llu ms, now %llu ms, diff %lld ms (drop=%d)\n",
									(unsigned long long)(pts / 1000000),
									(unsigned long long)(now / 1000000),
									(long long)((now - pts) / 1000000), drop);
							}
						}
					} else {
						f->rtp_ts = 0; /* Fallback will be handled in mix */
					}

					if (drop) {
						free(f->buf);
						free(f);
					} else {
						f->is_keyframe = !GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DELTA_UNIT);

						if (f->is_keyframe) {
							lwsl_notice("DIAGNOSTIC: Encoded H264 KEYFRAME! size=%zu for room %s\n", info.size, r->name);
						}

						pthread_mutex_lock(&r->encode_mutex);
						lws_dll2_add_tail(&f->list, &r->h264_queue);
						pthread_mutex_unlock(&r->encode_mutex);

						static int dbg_enc = 0;
						if (dbg_enc++ % 100 == 0)
							lwsl_notice("Encoded H264 frame: %zu bytes for room %s (pts %llu)\n", info.size, r->name, (unsigned long long)pts);
					}
				} else {
					free(f);
				}
			}
			gst_buffer_unmap(buffer, &info);
		}
		gst_sample_unref(sample);
	}
	return GST_FLOW_OK;
}

static GstFlowReturn
on_new_sample_av1(GstElement *sink, struct mixer_room *r)
{
	GstSample *sample;
	g_signal_emit_by_name(sink, "pull-sample", &sample);
	if (sample) {
		GstBuffer *buffer = gst_sample_get_buffer(sample);
		GstMapInfo info;
		if (gst_buffer_map(buffer, &info, GST_MAP_READ)) {
			struct mixer_encoded_frame *f = calloc(1, sizeof(*f));
			if (f) {
				f->buf = malloc(info.size);
				if (f->buf) {
					memcpy(f->buf, info.data, info.size);
					f->len = info.size;

					GstClockTime pts = GST_BUFFER_PTS(buffer);

					/* Drop massive catch-up bursts from compositor when a room is re-joined after being empty */
					int drop = 0;
					if (GST_CLOCK_TIME_IS_VALID(pts)) {
						f->rtp_ts = (uint32_t)(pts * 9 / 100000);
						GstClock *clock = gst_element_get_clock(sink);
						if (clock) {
							GstClockTime now = gst_clock_get_time(clock) - gst_element_get_base_time(sink);
							gst_object_unref(clock);
							if (now > pts + 1000000000ull) {
								drop = 1;
							}
						}
					} else {
						f->rtp_ts = 0;
					}

					if (drop) {
						free(f->buf);
						free(f);
					} else {
						f->is_keyframe = !GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DELTA_UNIT);

						pthread_mutex_lock(&r->encode_mutex);
						lws_dll2_add_tail(&f->list, &r->av1_queue);
						pthread_mutex_unlock(&r->encode_mutex);
					}
				} else {
					free(f);
				}
			}
			gst_buffer_unmap(buffer, &info);
		}
		gst_sample_unref(sample);
	}
	return GST_FLOW_OK;
}

int
mixer_room_init(struct mixer_room *r)
{
	GError *err = NULL;

	if (!gst_is_initialized())
		gst_init(NULL, NULL);

	pthread_mutex_init(&r->encode_mutex, NULL);
	lws_dll2_owner_clear(&r->h264_queue);
	lws_dll2_owner_clear(&r->av1_queue);

	r->pipeline = gst_parse_launch(r->vhd->pipeline_template, &err);
	if (!r->pipeline) {
		lwsl_err("%s: GStreamer pipeline parse failed: %s\n", __func__, err ? err->message : "Unknown");
		if (err) g_error_free(err);
		return -1;
	}

	lwsl_err("Using PVO Pipeline String: %s\n", r->vhd->pipeline_template);



	GstBus *bus = gst_element_get_bus(r->pipeline);
	gst_bus_add_watch(bus, (GstBusFunc)bus_call, r);
	gst_object_unref(bus);

	r->compositor = gst_bin_get_by_name(GST_BIN(r->pipeline), "comp");
	if (!r->compositor) {
		lwsl_err("%s: Failed to find compositor 'comp' in pipeline\n", __func__);
		return -1;
	}
	/* Ensure compositor aligns output PTS with the first incoming frame's PTS to avoid catch-up gaps */
	g_object_set(G_OBJECT(r->compositor), "start-time-selection", 1, NULL); // 1 = first

	GstPad *comp_src = gst_element_get_static_pad(r->compositor, "src");
	gst_pad_add_probe(comp_src, GST_PAD_PROBE_TYPE_BUFFER, on_compositor_src_buffer_probe, r, NULL);
	gst_object_unref(comp_src);

	/* Find sinks. Try 'outsink_h264' first, fallback to 'outsink' */
	r->appsink_h264 = gst_bin_get_by_name(GST_BIN(r->pipeline), "outsink_h264");
	if (!r->appsink_h264)
		r->appsink_h264 = gst_bin_get_by_name(GST_BIN(r->pipeline), "outsink");

	r->appsink_av1 = gst_bin_get_by_name(GST_BIN(r->pipeline), "outsink_av1");

	if (r->appsink_h264) {
		g_object_set(G_OBJECT(r->appsink_h264), "emit-signals", TRUE, "sync", FALSE, "async", FALSE, NULL);
		g_signal_connect(r->appsink_h264, "new-sample", G_CALLBACK(on_new_sample_h264), r);


	}

	if (r->appsink_av1) {
		g_object_set(G_OBJECT(r->appsink_av1), "emit-signals", TRUE, "sync", FALSE, "async", FALSE, NULL);
		g_signal_connect(r->appsink_av1, "new-sample", G_CALLBACK(on_new_sample_av1), r);
	}

	GstStateChangeReturn sret = gst_element_set_state(r->pipeline, GST_STATE_PLAYING);
	lwsl_notice("%s: Pipeline set to PLAYING, result %d\n", __func__, sret);

	r->lm_ops = &lm_speaker_ops;
	if (r->lm_ops->create) {
		r->lm_ctx = r->lm_ops->create(r);
	}

	return 0;
}

static void
free_chat_history(struct mixer_room *r)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&r->chat_history)) {
		struct chat_message *cm = lws_container_of(d, struct chat_message, list);
		lws_dll2_remove(&cm->list);
		free(cm->sender);
		free(cm->text);
		free(cm);
	} lws_end_foreach_dll_safe(d, d1);
}

void
mixer_room_deinit(struct mixer_room *r)
{
	if (r->lm_ops && r->lm_ops->destroy) {
		r->lm_ops->destroy(r->lm_ctx);
		r->lm_ctx = NULL;
	}

	if (r->pipeline) {
		gst_element_set_state(r->pipeline, GST_STATE_NULL);
		if (r->compositor) gst_object_unref(r->compositor);
		if (r->appsink_h264) gst_object_unref(r->appsink_h264);
		if (r->appsink_av1) gst_object_unref(r->appsink_av1);
		gst_object_unref(r->pipeline);
		r->pipeline = NULL;
	}

	if (r->adapt_h264) lws_adapt_destroy(&r->adapt_h264);

	pthread_mutex_destroy(&r->encode_mutex);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&r->h264_queue)) {
		struct mixer_encoded_frame *f = lws_container_of(d, struct mixer_encoded_frame, list);
		lws_dll2_remove(&f->list);
		free(f->buf);
		free(f);
	} lws_end_foreach_dll_safe(d, d1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&r->av1_queue)) {
		struct mixer_encoded_frame *f = lws_container_of(d, struct mixer_encoded_frame, list);
		lws_dll2_remove(&f->list);
		free(f->buf);
		free(f);
	} lws_end_foreach_dll_safe(d, d1);

	free_chat_history(r);
}

void
on_decoder_pad_added(GstElement *element, GstPad *new_pad, gpointer data)
{
	/* This is only for decodebin fallback */
	struct mixer_media_session *s = (struct mixer_media_session *)data;
	struct participant *p = (struct participant *)s->parent_p;

	if (p && p->room && p->room->compositor) {
		if (!s->compositor_pad) {
			s->compositor_pad = gst_element_request_pad_simple(p->room->compositor, "sink_%u");
			if (p->room->participants.count <= 1) p->room->master_pts = 0;
		}

		/* Link: decoder -> compositor_sink */
		GstPadLinkReturn ret = gst_pad_link(new_pad, s->compositor_pad);
		if (GST_PAD_LINK_FAILED(ret)) {
			lwsl_err("%s: Failed to link decoder to compositor (err %d)\n", __func__, ret);
		}
	}
}

int
init_participant_media(struct participant *p, enum lws_video_codec codec)
{
	int err;
	struct mixer_media_session *s = p->session;

	if (!s) return -1;

	/* 1. Init Opus Codecs */
	if (!s->decoder) {
		s->decoder = opus_decoder_create(AUDIO_RATE, AUDIO_CHANNELS, &err);
		if (err != OPUS_OK) lwsl_err("%s: Opus decoder create failed: %d\n", __func__, err);
	}

	if (!s->encoder) {
		s->encoder = opus_encoder_create(AUDIO_RATE, AUDIO_CHANNELS, OPUS_APPLICATION_VOIP, &err);
		if (err != OPUS_OK) {
			lwsl_err("%s: Opus encoder create failed: %d\n", __func__, err);
		} else {
			opus_encoder_ctl(s->encoder, OPUS_SET_BITRATE(20000));
			opus_encoder_ctl(s->encoder, OPUS_SET_VBR(0)); /* CBR for maximum compatibility */
			opus_encoder_ctl(s->encoder, OPUS_SET_COMPLEXITY(10));
			opus_encoder_ctl(s->encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
			opus_encoder_ctl(s->encoder, OPUS_SET_INBAND_FEC(0));
		}
	}

	/* 2. Init Video Decoder via GStreamer */
	s->last_dec_codec = codec;

	if (s->appsrc) {
		/* Already initialized */
		return 0;
	}

	s->last_pts = GST_CLOCK_TIME_NONE;
	char n_appsrc[64], n_dec[64], n_que[64], n_parse[64], n_deint[64], n_vconv[64], n_vscale[64], n_vrate[64], n_cfilt[64];
	lws_snprintf(n_appsrc, sizeof(n_appsrc), "appsrc_%p", s);
	lws_snprintf(n_dec, sizeof(n_dec), "dec_%p", s);
	lws_snprintf(n_que, sizeof(n_que), "que_%p", s);
	lws_snprintf(n_parse, sizeof(n_parse), "parse_%p", s);
	lws_snprintf(n_deint, sizeof(n_deint), "deint_%p", s);
	lws_snprintf(n_vconv, sizeof(n_vconv), "vconv_%p", s);
	lws_snprintf(n_vscale, sizeof(n_vscale), "vscale_%p", s);
	lws_snprintf(n_vrate, sizeof(n_vrate), "vrate_%p", s);
	lws_snprintf(n_cfilt, sizeof(n_cfilt), "cfilt_%p", s);

	s->appsrc = gst_element_factory_make("appsrc", n_appsrc);
	s->decodebin = gst_element_factory_make("avdec_h264", n_dec);
	if (!s->decodebin) {
		lwsl_err("%s: Critical: avdec_h264 not found, cannot build static chain\n", __func__);
		return -1;
	}
	GstElement *que = gst_element_factory_make("queue", n_que);
	g_object_set(G_OBJECT(que), "max-size-buffers", 0, "max-size-time", (guint64)0, "max-size-bytes", (guint)0, NULL);

	GstElement *h264parse = gst_element_factory_make("h264parse", n_parse);

	GstElement *deint = gst_element_factory_make("deinterlace", n_deint);
	GstElement *vconv = gst_element_factory_make("videoconvert", n_vconv);
	GstElement *vscale = gst_element_factory_make("videoscale", n_vscale);
	GstElement *vrate = gst_element_factory_make("videorate", n_vrate);
	GstElement *cfilter = gst_element_factory_make("capsfilter", n_cfilt);

	if (!s->appsrc || !s->decodebin || !que || !h264parse || !deint || !vconv || !vscale || !vrate || !cfilter) {
		lwsl_err("%s: Failed to create GStreamer elements\n", __func__);
		return -1;
	}

	/* Force progressive I420 and EXACTLY 25fps for the compositor */
	GstCaps *icaps = gst_caps_from_string("video/x-raw,format=I420,interlace-mode=progressive,framerate=25/1");
	g_object_set(G_OBJECT(cfilter), "caps", icaps, NULL);
	gst_caps_unref(icaps);

	GstCaps *caps = gst_caps_new_simple("video/x-h264",
			"stream-format", G_TYPE_STRING, "byte-stream",
			"alignment", G_TYPE_STRING, "au",
			NULL);
	g_object_set(G_OBJECT(s->appsrc), "caps", caps, "format", GST_FORMAT_TIME,
			"is-live", TRUE, "do-timestamp", FALSE, NULL);
	gst_caps_unref(caps);

	if (p->room && p->room->pipeline) {
		/* Use system clock for maximum stability with live jittery streams */
		gst_pipeline_use_clock(GST_PIPELINE(p->room->pipeline), gst_system_clock_obtain());

		if (!s->compositor_pad) {
			s->compositor_pad = gst_element_request_pad_simple(p->room->compositor, "sink_%u");
			if (p->room->participants.count <= 1) p->room->master_pts = 0;
		}

		/* Set compositor pad to be as lenient as possible */
		g_object_set(G_OBJECT(p->room->compositor), "latency", (GstClockTime)0, NULL);

		gst_bin_add_many(GST_BIN(p->room->pipeline), s->appsrc, que, h264parse, s->decodebin, deint, vconv, vscale, vrate, cfilter, NULL);

		/* Direct link: appsrc -> que -> h264parse -> avdec_h264 -> deinterlace -> vconv -> vscale -> videorate -> cfilter */
		if (!gst_element_link_many(s->appsrc, que, h264parse, s->decodebin, deint, vconv, vscale, vrate, cfilter, NULL)) {
			lwsl_err("%s: Failed to link static participant chain\n", __func__);
		}

		/* Link the end of our chain to the compositor */
		GstPad *cf_src = gst_element_get_static_pad(cfilter, "src");
		GstPadLinkReturn ret = gst_pad_link(cf_src, s->compositor_pad);
		gst_object_unref(cf_src);

		if (GST_PAD_LINK_FAILED(ret)) {
			lwsl_err("%s: Failed to link chain to compositor (err %d)\n", __func__, ret);
		}

		/* Add diagnostic probes */
		GstPad *srcpad = gst_element_get_static_pad(s->appsrc, "src");
		gst_pad_add_probe(srcpad, GST_PAD_PROBE_TYPE_BUFFER, on_appsrc_buffer_probe, s, NULL);
		gst_object_unref(srcpad);

		GstPad *dec_src = gst_element_get_static_pad(s->decodebin, "src");
		gst_pad_add_probe(dec_src, GST_PAD_PROBE_TYPE_BUFFER, on_decodebin_buffer_probe, s, NULL);
		gst_object_unref(dec_src);

		gst_element_sync_state_with_parent(s->appsrc);
		gst_element_sync_state_with_parent(que);
		gst_element_sync_state_with_parent(h264parse);
		gst_element_sync_state_with_parent(s->decodebin);
		gst_element_sync_state_with_parent(deint);
		gst_element_sync_state_with_parent(vconv);
		gst_element_sync_state_with_parent(vscale);
		gst_element_sync_state_with_parent(vrate);
		gst_element_sync_state_with_parent(cfilter);

		GstState state;
		gst_element_get_state(p->room->pipeline, &state, NULL, 0);
		if (state != GST_STATE_PLAYING) {
			lwsl_notice("Resuming pipeline on first media frame for room %s\n", p->room->name);
			gst_element_set_state(p->room->pipeline, GST_STATE_PLAYING);
		}
	}

	lws_dll2_owner_clear(&s->video_queue);
	lws_dll2_owner_clear(&s->rtp_queue);

	s->video_buf            = NULL;
	s->video_len            = 0;
	s->video_alloc          = 0;
	s->obu_buf              = NULL;

	s->audio_seen           = 0;

	s->obu_len              = 0;
	s->obu_alloc            = 0;

	s->last_dec_w           = 0;
	s->last_dec_h           = 0;
	s->last_dst_w           = 0;
	s->last_dst_h           = 0;

	if (!s->ring_pcm) {
		/* Initialize Audio Jitter Buffer */
		size_t elem_count = 100 * AUDIO_SAMPLES_PER_FRAME; /* 2000ms buffer */
		s->ring_buffer = malloc(elem_count * sizeof(int16_t));
		if (!s->ring_buffer) {
			lwsl_err("%s: OOM ring buffer\n", __func__);
			return -1;
		}
		s->ring_pcm = lws_ring_create(sizeof(int16_t), elem_count, NULL);
		if (!s->ring_pcm) {
			free(s->ring_buffer);
			s->ring_buffer = NULL;
			return -1;
		}
		s->ring_pcm_tail = 0;
	}

	s->audio_energy = 0;
	s->has_pcm = 0;

	return 0;
}

/* Old deinit removed */

void
deinit_participant_media(struct participant *p)
{
    if (p->session) {
        p->session->parent_p = NULL;

        /* Defer destruction to the worker thread safely */
        if (p->room && p->room->vhd) {
            struct mixer_msg msg;
            memset(&msg, 0, sizeof(msg));
            msg.type = MSG_REMOVE_SESSION;
            msg.session = p->session;

            lws_mutex_lock(p->room->vhd->mutex_rx);
            if (lws_ring_insert(p->room->vhd->ring_rx, &msg, 1) != 1) {
                lwsl_err("%s: Failed to insert REMOVE_SESSION\n", __func__);
                mixer_media_session_unref(p->session);
            }
            lws_mutex_unlock(p->room->vhd->mutex_rx);
        } else {
            /* Fallback if somehow room is missing */
            mixer_media_session_unref(p->session);
        }

        p->session = NULL;
    }
}

void
mixer_force_keyframe(struct mixer_room *r)
{
	if (!r || !r->pipeline || !r->appsink_h264) return;

	/*
	 * Send an UPSTREAM event starting from the sink.
	 * This flows backwards to the encoder (x264enc) without requiring the
	 * STREAM_LOCK, completely avoiding deadlocks with the data thread.
	 */
	GstEvent *event = gst_event_new_custom(GST_EVENT_CUSTOM_UPSTREAM,
		gst_structure_new_empty("GstForceKeyUnit"));

	gboolean res = gst_element_send_event(r->appsink_h264, event);
	lwsl_notice("DIAGNOSTIC: Forced keyframe on video encoder (res=%d)\n", res);
}
