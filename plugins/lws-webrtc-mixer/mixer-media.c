#include <libwebsockets.h>
#include <pthread.h>

#include <string.h>
#include <stdlib.h>


#include "mixer-media.h"

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

	if (s->tcc_dec) lws_transcode_destroy(&s->tcc_dec);
	if (s->avframe_dec) lws_transcode_frame_free(&s->avframe_dec);
	if (s->avframe_tmp) lws_transcode_frame_free(&s->avframe_tmp);
	if (s->sws_ctx_dec) lws_transcode_scaler_destroy(&s->sws_ctx_dec);
	if (s->avframe_scaled) lws_transcode_frame_free(&s->avframe_scaled);

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

static void
blit_yuv(void *dst, void *src, int dst_x, int dst_y)
{
	int i;
	uint8_t **src_data = lws_transcode_frame_get_data(src);
	int *src_ls = lws_transcode_frame_get_linesize(src);
	int src_w = lws_transcode_frame_get_width(src);
	int src_h = lws_transcode_frame_get_height(src);
	uint8_t **dst_data = lws_transcode_frame_get_data(dst);
	int *dst_ls = lws_transcode_frame_get_linesize(dst);

	for (i = 0; i < src_h; i++) {
		uint8_t *s = src_data[0] + i * src_ls[0];
		memcpy(dst_data[0] + (dst_y + i) * dst_ls[0] + dst_x,
		       s, (size_t)src_w);
	}
	for (i = 0; i < src_h / 2; i++) {
		memcpy(dst_data[1] + (dst_y / 2 + i) * dst_ls[1] + (dst_x / 2),
		       src_data[1] + i * src_ls[1], (size_t)src_w / 2);
		memcpy(dst_data[2] + (dst_y / 2 + i) * dst_ls[2] + (dst_x / 2),
		       src_data[2] + i * src_ls[2], (size_t)src_w / 2);
	}
}

static struct lws_transcode_ctx *
mixer_create_encoder(enum lws_video_codec codec, uint32_t w, uint32_t h)
{
	struct lws_transcode_info info;

	memset(&info, 0, sizeof(info));
	info.codec = codec == LWS_CODEC_AV1 ? LWS_TCC_AV1 : LWS_TCC_H264;
	info.width = w;
	info.height = h;
	info.fps = 30;
	info.bitrate = 1000000;

	return lws_transcode_encoder_create(&info);
}

static int
count_codec_participants(struct lws_dll2 *d, void *user)
{
    struct codec_counts *cc = (struct codec_counts *)user;
    struct participant *p = lws_container_of(d, struct participant, list);

	if (p->pss && we_ops) {
		if (we_ops->get_video_pt_av1 && we_ops->get_video_pt_av1(p->pss)) {
			cc->av1++;
		}
		if (we_ops->get_video_pt_h264 && we_ops->get_video_pt_h264(p->pss)) {
			cc->h264++;
		}
	}
    return 0;
}

static int
compose_participant(struct lws_dll2 *d, void *user)
{
    struct compose_data *cd = (struct compose_data *)user;
    struct participant *p = lws_container_of(d, struct participant, list);
    int w = 0, h = 0;

    if (p->session && p->session->avframe_scaled) {
        w = lws_transcode_frame_get_width(p->session->avframe_scaled);
        h = lws_transcode_frame_get_height(p->session->avframe_scaled);

        /* Simple Grid Logic: 2x2 */
        /* If we exceed bounds, just don't draw or overlay (simple for now) */

        blit_yuv(cd->room->master_frame, p->session->avframe_scaled, cd->x_off, cd->y_off);

        cd->x_off += w;
        if (cd->x_off >= (int)cd->room->master_w) {
            cd->x_off = 0;
            cd->y_off += h;
        }
    }
    return 0;
}
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
		if (!lws_dll2_is_detached(&s->list)) {
			lws_dll2_remove(&s->list);
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
						lws_ring_insert(s->ring_pcm, s->pcm_in, (size_t)ret);
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
			/* Handle Video logic */

			if (!s->tcc_dec) {
				/* Check Payload Type */
				//uint8_t pt = ((uint8_t *)msg->payload)[1] & 0x7F;
				enum lws_transcode_codec codec_type;

				/* Use resolved codec from mixer_on_media */
				if (msg->codec == LWS_CODEC_AV1) {
					codec_type = LWS_TCC_AV1;
					s->last_dec_codec = LWS_CODEC_AV1;
				} else if (msg->codec == LWS_CODEC_H264) {
					codec_type = LWS_TCC_H264;
					s->last_dec_codec = LWS_CODEC_H264;
				} else {
					/* Fallback or Unknown */
					lwsl_warn("%s: Unknown Codec for PT %d\n", __func__, ((uint8_t *)msg->payload)[1] & 0x7F);
					/* Should we try to guess? No, safer to fail or improve resolution in on_media */
					/* For now, if 0, assume H264? No, AV1 is 99. */
					/* Let's leave it null to fail safely. */
					goto skip_decoding;
				}

				s->tcc_dec = lws_transcode_decoder_create(codec_type);
				if (!s->tcc_dec) {
					lwsl_err("%s: Failed to create decoder (codec %d)\n", __func__, msg->codec);
				} else {
					lwsl_notice("%s: Created Decoder for Codec %d\n", __func__, msg->codec);
					/* Alloc frame holder (arbitrary size, decoder should handle?) */
					/* Actually lws_transcode_frame_alloc might need max size or initial specific size */
					s->avframe_dec = lws_transcode_frame_alloc(1280, 720);
				}
			}

			if (s->tcc_dec && s->avframe_dec) {
				/*
				 * lws_transcode_decode returns:
				 * 0: Frame decoded
				 * 1: Need more data / no frame produced yet
				 * <0: Error
				 */

				uint8_t *in_data = ((uint8_t *)msg->payload);
				size_t in_len = msg->len;
				int ready_to_decode = 1;

				if (msg->codec == LWS_CODEC_H264 && in_len > 0) {
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

									static int dbg_fua1 = 0;
									if (dbg_fua1++ % 500 == 0)
										lwsl_notice("FU-A: Start fragment, NAL type %u, len %zu\n", nal_type, payload_len);
								}
							} else if (s->video_buf && s->video_len > 0) {
								/* Middle or end of fragment */
								size_t needed = s->video_len + payload_len;
								if (s->video_alloc < needed) {
									s->video_buf = realloc(s->video_buf, needed + 4096);
									s->video_alloc = needed + 4096;
								}
								if (s->video_buf) {
									memcpy(s->video_buf + s->video_len, payload, payload_len);
									s->video_len += payload_len;

									static int dbg_fua2 = 0;
									if (dbg_fua2++ % 2000 == 0)
										lwsl_notice("FU-A: Cont fragment, len %zu\n", payload_len);
								}
								/* We don't decode on 'E', we decode on 'marker' */
							}
						}
					}

					if (msg->marker && s->video_buf && s->video_len > 0) {
						in_data = s->video_buf;
						in_len = s->video_len;
						ready_to_decode = 1;

						static int dbg_marker = 0;
						if (dbg_marker++ % 50 == 0)
							lwsl_notice("H264 Marker Received! Feeding Frame to decoder (len %zu)\n", in_len);
					}
				} else if (msg->codec == LWS_CODEC_AV1 && in_len > 1) {
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
						if (s->video_buf && s->video_len > 0) {
							in_data = s->video_buf;
							in_len = s->video_len;
							ready_to_decode = 1;
						}
					}
				}

				if (ready_to_decode) {
					int r = lws_transcode_decode(s->tcc_dec, in_data, in_len, s->avframe_dec);

					if (r == 0) {
						/* We got a frame! */
						s->decoded_frames++;
						s->processed_frames_count++;
#if 0
						if (s->decoded_frames % 50 == 0)
							lwsl_notice("Decoder produced frame %llu\n", (unsigned long long)s->decoded_frames);
#endif
					} else if (r == -11) { /* AVERROR(EAGAIN) */
						static int dbg_buff = 0;
						if (dbg_buff++ % 100 == 0)
							lwsl_notice("Decoder buffering... (EAGAIN)\n");
					} else if (r < 0) {
						/* Reducing log spam */
						if (s->decoded_frames == 0 || s->decoded_frames % 100 == 0)
							lwsl_warn("%s: Decoder Error %d (len %zu)\n", __func__, r, in_len);
					}
					/* Reset buffer for next frame */
					s->video_len = 0;
				}

			}

skip_decoding:;
		}

		if (msg->payload) free(msg->payload);
	}
}

static void
process_room_mix(struct vhd_mixer *vhd, struct mixer_room *r, lws_usec_t deadline)
{
	/* 1. Sum Audio */
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

			static int audio_enc_log = 0;
			if (audio_enc_log++ % 100 == 0 && s->has_pcm) {
				lwsl_notice("%s: Encoded Audio for %s (ret %d, input energy %u)\n",
						__func__, s->room_name, ret, (unsigned int)s->audio_energy);
			}

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
	if ((r->master_pts & 1) == 0) { /* 25fps */

		/* Broadcast previously encoded frames */
		pthread_mutex_lock(&r->enc_thread_h264.mutex);
		if (r->enc_thread_h264.encode_done) {
			uint8_t *buf = r->enc_thread_h264.encoded_buf;
			size_t len = r->enc_thread_h264.encoded_len;
			uint32_t rtp_ts = r->enc_thread_h264.encoded_rtp_pts;
			
			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
				struct mixer_media_session *s = lws_container_of(d, struct mixer_media_session, list);
				if (strcmp(s->room_name, r->name)) goto next_tx_h264;
				if (s->can_rx_h264) {
					if (s->media && we_ops && we_ops->send_video) {
						we_ops->send_video(s->media, buf, len, LWS_CODEC_H264, rtp_ts);
					}
				}
next_tx_h264:;
			} lws_end_foreach_dll(d);

			r->enc_thread_h264.encode_done = 0;
		}
		pthread_mutex_unlock(&r->enc_thread_h264.mutex);

		pthread_mutex_lock(&r->enc_thread_av1.mutex);
		if (r->enc_thread_av1.encode_done) {
			uint8_t *buf = r->enc_thread_av1.encoded_buf;
			size_t len = r->enc_thread_av1.encoded_len;
			uint32_t rtp_ts = r->enc_thread_av1.encoded_rtp_pts;
			
			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
				struct mixer_media_session *s = lws_container_of(d, struct mixer_media_session, list);
				if (strcmp(s->room_name, r->name)) goto next_tx_av1;
				if (s->can_rx_av1) {
					if (s->media && we_ops && we_ops->send_video) {
						we_ops->send_video(s->media, buf, len, LWS_CODEC_AV1, rtp_ts);
					}
				}
next_tx_av1:;
			} lws_end_foreach_dll(d);

			r->enc_thread_av1.encode_done = 0;
		}
		pthread_mutex_unlock(&r->enc_thread_av1.mutex);

		/* Video Frame Drop logic to protect real-time Audio */
		lws_usec_t mix_now = lws_now_usecs();
		if (mix_now > deadline + 20000) {
			static int warned = 0;
			if (warned++ % 100 == 0) {
				lwsl_notice("%s: CPU heavily loaded! Dropping Video Frame to preserve Audio (Behind %llums)\n",
						__func__, (unsigned long long)((mix_now - deadline)/1000));
			}
			return;
		}

		/* Count Active Sources (Logic adapted from count_codec_participants) */
		int count_h264 = 0;
		int count_av1 = 0;
		int count_joined_total = 0;

		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
			struct mixer_media_session *s = lws_container_of(d, struct mixer_media_session, list);
			if (strcmp(s->room_name, r->name))
                                goto next_codec_count;

			if (s->joined)
                                count_joined_total++;

			// static int pass_log = 0;
			// if (pass_log++ % 200 == 0) {
			//	lwsl_notice("%s: DIAGNOSTIC pass s->joined=%d, out_only=%d, can_h264=%d, can_av1=%d (frames %llu) for peer in room\n",
			//		__func__, s->joined, s->out_only, s->can_rx_h264, s->can_rx_av1, (unsigned long long)s->decoded_frames);
			//}

			if (!s->joined && !s->out_only)
                                goto next_codec_count;

			if (s->can_rx_h264)
                                count_h264++;
			if (s->can_rx_av1)
                                count_av1++;

next_codec_count:;
		} lws_end_foreach_dll(d);

		// static int mix_log = 0;
		// if (mix_log++ % 200 == 0) {
		//	lwsl_notice("%s: DIAGNOSTIC room '%s' joined_total=%d, active_h264=%d, active_av1=%d\n",
		//			__func__, r->name, count_joined_total, count_h264, count_av1);
		//}

		if (count_h264 > 0 || count_av1 > 0) {
			/* Ensure Encoders */
			if (count_h264 > 0 && !r->tcc_enc_h264)
				r->tcc_enc_h264 = mixer_create_encoder(LWS_CODEC_H264, r->master_w, r->master_h);
			if (count_av1 > 0 && !r->tcc_enc_av1)
				r->tcc_enc_av1 = mixer_create_encoder(LWS_CODEC_AV1, r->master_w, r->master_h);

			/* Clear Background */
			uint8_t **m_data = lws_transcode_frame_get_data(r->master_frame);
			int *m_ls = lws_transcode_frame_get_linesize(r->master_frame);
			int m_h = lws_transcode_frame_get_height(r->master_frame);

                        memset(m_data[0], 0, (size_t)m_ls[0] * (size_t)m_h);
			memset(m_data[1], 128, (size_t)m_ls[1] * (size_t)m_h / 2);
			memset(m_data[2], 128, (size_t)m_ls[2] * (size_t)m_h / 2);

			/* Compose */
			r->lm_ops->update(r, r->lm_ctx);
			int num_regions = 0;
			const struct lws_mixer_layout_region *regions = r->lm_ops->get_regions(r->lm_ctx, &num_regions);
			
			for (int i = 0; i < num_regions; i++) {
				const struct lws_mixer_layout_region *reg = &regions[i];
				struct mixer_media_session *s = reg->s;

				if (s->avframe_dec && s->decoded_frames > 0) {
					int slot_w = reg->w;
					int slot_h = reg->h;
					int x = reg->x;
					int y = reg->y;

					/* Scale & Blit (Simplified for brevity, same as original) */
					// ... (Assume blit_yuv and scaling logic exists, specialized for session)
					// Copy-paste scaling logic?
					int src_w = (int)lws_transcode_frame_get_width(s->avframe_dec);
					int src_h = (int)lws_transcode_frame_get_height(s->avframe_dec);
					int dst_w = slot_w; int dst_h = slot_h;

					if (src_w * slot_h > slot_w * src_h) { dst_h = (src_h * slot_w) / src_w; dst_h &= ~1; }
					else { dst_w = (src_w * slot_h) / src_h; dst_w &= ~1; }

					if (dst_w < 2) dst_w = 2;
					if (dst_h < 2) dst_h = 2;

					int off_x = (slot_w - dst_w) / 2; off_x &= ~1;
					int off_y = (slot_h - dst_h) / 2; off_y &= ~1;

					if (!s->sws_ctx_dec || s->last_dec_w != src_w || s->last_dec_h != src_h || s->last_dst_w != dst_w || s->last_dst_h != dst_h) {
						if (s->sws_ctx_dec) lws_transcode_scaler_destroy(&s->sws_ctx_dec);
						s->sws_ctx_dec = lws_transcode_scaler_create((uint32_t)src_w, (uint32_t)src_h, (uint32_t)dst_w, (uint32_t)dst_h);
						s->last_dec_w = src_w; s->last_dec_h = src_h;
						s->last_dst_w = dst_w; s->last_dst_h = dst_h;
						if (s->avframe_scaled) lws_transcode_frame_free(&s->avframe_scaled);
						s->avframe_scaled = lws_transcode_frame_alloc((uint32_t)dst_w, (uint32_t)dst_h);
					}

					if (s->sws_ctx_dec && s->avframe_scaled) {
						lws_transcode_scale(s->sws_ctx_dec, s->avframe_dec, s->avframe_scaled);
						void blit_yuv(void *dst, void *src, int dx, int dy); /* Declared higher up usually, or provided by lws */
						blit_yuv(r->master_frame, s->avframe_scaled, x + off_x, y + off_y);
					}
				}
			}

			/* Trigger H264 Enable */
			if (r->tcc_enc_h264 && count_h264 > 0) {
				pthread_mutex_lock(&r->enc_thread_h264.mutex);
				if (!r->enc_thread_h264.frame_ready) {
					uint8_t **m_data = lws_transcode_frame_get_data(r->master_frame);
					int *m_ls = lws_transcode_frame_get_linesize(r->master_frame);
					uint8_t **e_data = lws_transcode_frame_get_data(r->enc_thread_h264.enc_frame);
					int *e_ls = lws_transcode_frame_get_linesize(r->enc_thread_h264.enc_frame);
					int m_h = lws_transcode_frame_get_height(r->master_frame);

					for (int p=0; p<3; p++) {
						int h = p == 0 ? m_h : m_h / 2;
						int copy_len = m_ls[p] < e_ls[p] ? m_ls[p] : e_ls[p];
						for (int y=0; y<h; y++) {
							memcpy(e_data[p] + y * e_ls[p], m_data[p] + y * m_ls[p], (size_t)copy_len);
						}
					}
					r->enc_thread_h264.rtp_pts = (uint32_t)((r->master_pts / 2) * 3600);
					r->enc_thread_h264.frame_ready = 1;
					pthread_cond_signal(&r->enc_thread_h264.cond);
				} else {
					static int dbg_drop_h264 = 0;
					if (dbg_drop_h264++ % 50 == 0) lwsl_notice("Dropping H264 encode frame (encoder busy)\n");
				}
				pthread_mutex_unlock(&r->enc_thread_h264.mutex);
			}

			/* Trigger AV1 Encode */
			if (r->tcc_enc_av1 && count_av1 > 0) {
				pthread_mutex_lock(&r->enc_thread_av1.mutex);
				if (!r->enc_thread_av1.frame_ready) {
					uint8_t **m_data = lws_transcode_frame_get_data(r->master_frame);
					int *m_ls = lws_transcode_frame_get_linesize(r->master_frame);
					uint8_t **e_data = lws_transcode_frame_get_data(r->enc_thread_av1.enc_frame);
					int *e_ls = lws_transcode_frame_get_linesize(r->enc_thread_av1.enc_frame);
					int m_h = lws_transcode_frame_get_height(r->master_frame);

					for (int p=0; p<3; p++) {
						int h = p == 0 ? m_h : m_h / 2;
						int copy_len = m_ls[p] < e_ls[p] ? m_ls[p] : e_ls[p];
						for (int y=0; y<h; y++) {
							memcpy(e_data[p] + y * e_ls[p], m_data[p] + y * m_ls[p], (size_t)copy_len);
						}
					}
					r->enc_thread_av1.rtp_pts = (uint32_t)((r->master_pts / 2) * 3600);
					r->enc_thread_av1.frame_ready = 1;
					pthread_cond_signal(&r->enc_thread_av1.cond);
				} else {
					static int dbg_drop_av1 = 0;
					if (dbg_drop_av1++ % 50 == 0) lwsl_notice("Dropping AV1 encode frame (encoder busy)\n");
				}
				pthread_mutex_unlock(&r->enc_thread_av1.mutex);
			}

		}
	}
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
			usleep((useconds_t)diff);
			continue;
		}

		/* Catch up if way behind (e.g. debugger paused), jump to now to avoid massive bursts */
		if (now > next_frame_time && now - next_frame_time > 100000)
			next_frame_time = now;

		next_frame_time += 20000;

        /* 1. Process Control Messages (Add/Remove Sessions) */
        lws_mutex_lock(vhd->mutex_rx);
        while (lws_ring_get_count_waiting_elements(vhd->ring_rx, &vhd->ring_rx_tail) > 0) {
             msg = (struct mixer_msg *)lws_ring_get_element(vhd->ring_rx, &vhd->ring_rx_tail);
             process_control_message(vhd, msg);
             lws_ring_consume(vhd->ring_rx, &vhd->ring_rx_tail, NULL, 1);
             lws_ring_update_oldest_tail(vhd->ring_rx, vhd->ring_rx_tail);
        }
        lws_mutex_unlock(vhd->mutex_rx);

        /* Fast path: if there are no participants, don't waste CPU decoding/mixing */
        if (!lws_dll2_get_head(&vhd->sessions))
              continue;

        /* 2. Process Session Media (Decode) */
        lws_start_foreach_dll(struct lws_dll2 *, d_s, lws_dll2_get_head(&vhd->sessions)) {
             struct mixer_media_session *s = lws_container_of(d_s, struct mixer_media_session, list);
             process_session_media(s);
        } lws_end_foreach_dll(d_s);

        /* 3. Mix & Encode */
        lws_start_foreach_dll(struct lws_dll2 *, d_r, lws_dll2_get_head(&vhd->rooms)) {
            struct mixer_room *r = lws_container_of(d_r, struct mixer_room, list);
            process_room_mix(vhd, r, next_frame_time);
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

static void *
video_encoder_thread(void *d)
{
	struct encoder_thread *et = (struct encoder_thread *)d;

	while (et->running) {
		pthread_mutex_lock(&et->mutex);
		while (et->running && !et->frame_ready) {
			pthread_cond_wait(&et->cond, &et->mutex);
		}
		
		if (!et->running) {
			pthread_mutex_unlock(&et->mutex);
			break;
		}

		/* We have a frame to encode */
		et->frame_ready = 0;
		pthread_mutex_unlock(&et->mutex);

		uint8_t *buf;
		size_t len;
		struct lws_transcode_ctx *tcc = (et->codec == LWS_CODEC_H264) ? 
				et->room->tcc_enc_h264 : et->room->tcc_enc_av1;

		if (!tcc || !et->enc_frame) {
			continue;
		}

		if (lws_transcode_encode(tcc, et->enc_frame, &buf, &len) >= 0) {
			pthread_mutex_lock(&et->mutex);
			if (len > et->encoded_alloc) {
				et->encoded_alloc = len + 1048576; /* 1MB increment */
				et->encoded_buf = realloc(et->encoded_buf, et->encoded_alloc);
			}
			if (et->encoded_buf) {
				memcpy(et->encoded_buf, buf, len);
				et->encoded_len = len;
				et->encoded_rtp_pts = et->rtp_pts;
				et->encode_done = 1; /* Signal back to worker thread */
			}
			pthread_mutex_unlock(&et->mutex);
		}
	}

	return NULL;
}

static int
init_enc_thread(struct encoder_thread *et, struct mixer_room *r, enum lws_video_codec codec)
{
	et->room = r;
	et->codec = codec;
	et->running = 1;
	et->encode_done = 0;
	et->frame_ready = 0;
	et->encoded_buf = NULL;
	et->encoded_len = 0;
	et->encoded_alloc = 0;
	pthread_mutex_init(&et->mutex, NULL);
	pthread_cond_init(&et->cond, NULL);

	et->enc_frame = lws_transcode_frame_alloc(r->master_w, r->master_h);
	if (!et->enc_frame)
		return -1;

	if (pthread_create(&et->thread, NULL, video_encoder_thread, et)) {
		lws_transcode_frame_free(&et->enc_frame);
		return -1;
	}
	return 0;
}

static void
deinit_enc_thread(struct encoder_thread *et)
{
	if (et->running) {
		pthread_mutex_lock(&et->mutex);
		et->running = 0;
		pthread_cond_signal(&et->cond);
		pthread_mutex_unlock(&et->mutex);

		pthread_join(et->thread, NULL);
	}
	pthread_mutex_destroy(&et->mutex);
	pthread_cond_destroy(&et->cond);

	if (et->encoded_buf)
		free(et->encoded_buf);
	
	if (et->enc_frame)
		lws_transcode_frame_free(&et->enc_frame);
}

int
mixer_room_init(struct mixer_room *r)
{
	r->master_frame = lws_transcode_frame_alloc(r->master_w, r->master_h);
	if (!r->master_frame)
		return -1;

	init_enc_thread(&r->enc_thread_h264, r, LWS_CODEC_H264);
	init_enc_thread(&r->enc_thread_av1, r, LWS_CODEC_AV1);

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

	deinit_enc_thread(&r->enc_thread_h264);
	deinit_enc_thread(&r->enc_thread_av1);

	if (r->tcc_enc_h264) lws_transcode_destroy(&r->tcc_enc_h264);
	if (r->tcc_enc_av1) lws_transcode_destroy(&r->tcc_enc_av1);
	if (r->master_frame) lws_transcode_frame_free(&r->master_frame);

	free_chat_history(r);
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

	/* 2. Init Video Decoder */
	s->last_dec_codec = codec;
	if (s->tcc_dec) lws_transcode_destroy(&s->tcc_dec);

	s->tcc_dec = lws_transcode_decoder_create(codec == LWS_CODEC_AV1 ?
			LWS_TCC_AV1 : LWS_TCC_H264);
	if (!s->tcc_dec)
		return -1;

	if (!s->avframe_dec) s->avframe_dec = lws_transcode_frame_alloc(1280, 720);
	if (!s->avframe_tmp) s->avframe_tmp = lws_transcode_frame_alloc(1280, 720);
	s->avframe_scaled       = NULL;

	lws_dll2_owner_clear(&s->video_queue);
	lws_dll2_owner_clear(&s->rtp_queue);

	s->video_buf            = NULL;
	s->video_len            = 0;
	s->video_alloc          = 0;
	s->obu_buf              = NULL;

	s->audio_seen           = 0;

	s->obu_len              = 0;
	s->obu_alloc            = 0;

	s->sws_ctx_dec          = NULL;
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
            lws_ring_insert(p->room->vhd->ring_rx, &msg, 1);
            lws_mutex_unlock(p->room->vhd->mutex_rx);
        } else {
            /* Fallback if somehow room is missing */
            mixer_media_session_unref(p->session);
        }

        p->session = NULL;
    }
}

struct relay_mixed_data {
	struct mixer_room       *room;
	struct participant      *exclude;
	const uint8_t           *buf;
	size_t                  len;
	enum lws_webrtc_codec   codec;
	uint32_t                pts;
};

static int
send_video_to_participant(struct lws_dll2 *d, void *user)
{
	struct relay_mixed_data *rd = (struct relay_mixed_data *)user;
	struct participant *p = lws_container_of(d, struct participant, list);

	if (p != rd->exclude && p->pss) {
		if (p->out_only) return 0;
		/* Mirror incoming codec choice */
		int support = 0;
		if (rd->codec == LWS_CODEC_AV1 && we_ops && we_ops->get_video_pt_av1) {
			support = we_ops->get_video_pt_av1(p->pss);
		} else if (rd->codec == LWS_CODEC_H264 && we_ops && we_ops->get_video_pt_h264) {
			support = we_ops->get_video_pt_h264(p->pss);
		}
		
		if (!support) return 0;

		/* Queue IDR if requested (TODO) */

		/*
		 * We are in Worker Thread. We cannot call lws_write/we_ops directly.
		 * Push to TX Ring.
		 */
		struct mixer_msg msg;
		memset(&msg, 0, sizeof(msg));
		msg.type = MSG_VIDEO_FRAME;
		msg.session = p->session; /* Weak ref interaction needed? Session prevents PSS destruction? No. */
		msg.payload = malloc(rd->len);
		if (msg.payload) {
			memcpy(msg.payload, rd->buf, rd->len);
			msg.len = rd->len;
			msg.codec = (int)rd->codec;
			msg.timestamp = rd->pts;

			/* We need to pass the session back. */
			/* Issue: Message needs 'session' to identify target in LWS thread. */
			/* But we are iterating 'participants' here. p->session is available. */
			msg.session = p->session;

			mixer_media_session_ref(p->session); /* +1 for ring_tx */

			lws_mutex_lock(p->room->vhd->mutex_tx);
			if (lws_ring_insert(p->room->vhd->ring_tx, &msg, 1) != 1) {
				free(msg.payload);
				mixer_media_session_unref(p->session);
			}
			lws_mutex_unlock(p->room->vhd->mutex_tx);

			lws_cancel_service(we_ops->get_context(p->room->vhd->vhd));
		}
	}

	return 0;
}

int
media_compose_and_broadcast(struct mixer_room *r)
{
	/* We expect r is locked if necessary, or we should lock here? */
	/* Only if we access r->participants. We DO. */
	/* Assuming caller holds lock or we don't have one yet. */

	struct compose_data cd = { r, 0, 0 };
	struct codec_counts cc = { r, 0, 0, 0 };
	uint8_t *buf;
	size_t len;

	r->master_pts++;
	if (r->master_pts & 1)
		return 0;

	lws_dll2_foreach_safe(&r->participants, &cc, count_codec_participants);

	if (cc.h264 == 0 && cc.av1 == 0)
		return 0;

	if (cc.h264 > 0 && !r->tcc_enc_h264)
		r->tcc_enc_h264 = mixer_create_encoder(LWS_CODEC_H264, r->master_w, r->master_h);
#if defined(LWS_WITH_AV1_ENCODE)
	if (cc.av1 > 0 && !r->tcc_enc_av1)
		r->tcc_enc_av1 = mixer_create_encoder(LWS_CODEC_AV1, r->master_w, r->master_h);
#endif

	uint8_t **m_data = lws_transcode_frame_get_data(r->master_frame);
	int *m_ls = lws_transcode_frame_get_linesize(r->master_frame);
	int m_h = lws_transcode_frame_get_height(r->master_frame);

	memset(m_data[0], 0, (size_t)m_ls[0] * (size_t)m_h);
	memset(m_data[1], 128, (size_t)m_ls[1] * (size_t)m_h / 2);
	memset(m_data[2], 128, (size_t)m_ls[2] * (size_t)m_h / 2);

	lws_dll2_foreach_safe(&r->participants, &cd, compose_participant);

	uint32_t rtp_pts = (uint32_t)((r->master_pts / 2) * 3600);

	if (r->tcc_enc_h264 && cc.h264 > 0) {
		if (lws_transcode_encode(r->tcc_enc_h264, r->master_frame, &buf, &len) >= 0) {
			struct relay_mixed_data rd = { r, NULL, buf, len, LWS_WEBRTC_CODEC_H264, rtp_pts };
			lws_dll2_foreach_safe(&r->participants, &rd, send_video_to_participant);
		}
	}

#if defined(LWS_WITH_AV1_ENCODE)
	if (r->tcc_enc_av1 && cc.av1 > 0) {
		if (lws_transcode_encode(r->tcc_enc_av1, r->master_frame, &buf, &len) >= 0) {
			struct relay_mixed_data rd = { r, NULL, buf, len, LWS_WEBRTC_CODEC_AV1, rtp_pts };
			lws_dll2_foreach_safe(&r->participants, &rd, send_video_to_participant);
		}
	}
#endif

	return 0;
}
