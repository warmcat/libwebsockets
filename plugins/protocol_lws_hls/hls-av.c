#include "private-lws-hls.h"
#include <stdio.h>
#include <stdlib.h>

#define HLS_SEGMENT_DUR 10


void *
lws_hls_thumbnail_worker(void *d)
{
        struct per_vhost_data__lws_hls *vhd = (struct per_vhost_data__lws_hls *)d;

        while (1) {
                pthread_mutex_lock(&vhd->lock);
                
                while (!vhd->thread_exit && !vhd->task_head) {
                        pthread_cond_wait(&vhd->cond, &vhd->lock);
                }
                
                if (vhd->thread_exit) {
                        pthread_mutex_unlock(&vhd->lock);
                        break;
                }
                
                struct thumb_task *t = vhd->task_head;
                vhd->task_head = t->next;
                if (!vhd->task_head)
                        vhd->task_tail = NULL;
                        
                pthread_mutex_unlock(&vhd->lock);
                
                char filepath[512];
                snprintf(filepath, sizeof(filepath), "%s/%s", vhd->media_dir, t->filename);
                
                AVFormatContext *fmt_ctx = NULL;
                AVCodecContext *dec_ctx = NULL;
                AVCodecContext *enc_ctx = NULL;
                struct SwsContext *sws_ctx = NULL;
                AVFrame *frame = NULL;
                AVFrame *rgb_frame = NULL;
                AVPacket *pkt = NULL;
                AVPacket *enc_pkt = NULL;
                uint8_t *jpeg_data = NULL;
                int jpeg_size = 0;
                
                if (avformat_open_input(&fmt_ctx, filepath, NULL, NULL) == 0) {
                        if (avformat_find_stream_info(fmt_ctx, NULL) >= 0) {
                                int video_idx = -1;
                                for (unsigned int i = 0; i < fmt_ctx->nb_streams; i++) {
                                        if (fmt_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
                                                video_idx = (int)i;
                                                break;
                                        }
                                }
                                
                                if (video_idx >= 0) {
                                        const AVCodec *decoder = avcodec_find_decoder(fmt_ctx->streams[video_idx]->codecpar->codec_id);
                                        if (decoder) {
                                                dec_ctx = avcodec_alloc_context3(decoder);
                                                avcodec_parameters_to_context(dec_ctx, fmt_ctx->streams[video_idx]->codecpar);
                                                
                                                if (avcodec_open2(dec_ctx, decoder, NULL) == 0) {
                                                        frame = av_frame_alloc();
                                                        pkt = av_packet_alloc();
                                                        
                                                        while (av_read_frame(fmt_ctx, pkt) >= 0) {
                                                                if (pkt->stream_index == video_idx) {
                                                                        if (avcodec_send_packet(dec_ctx, pkt) == 0) {
                                                                                if (avcodec_receive_frame(dec_ctx, frame) == 0) {
                                                                                        const AVCodec *encoder = avcodec_find_encoder(AV_CODEC_ID_MJPEG);
                                                                                        if (encoder) {
                                                                                                enc_ctx = avcodec_alloc_context3(encoder);
                                                                                                enc_ctx->width = frame->width;
                                                                                                enc_ctx->height = frame->height;
                                                                                                enc_ctx->time_base = (AVRational){1, 25};
                                                                                                enc_ctx->pix_fmt = AV_PIX_FMT_YUVJ420P; 
                                                                                                
                                                                                                if (avcodec_open2(enc_ctx, encoder, NULL) == 0) {
                                                                                                        sws_ctx = sws_getContext(frame->width, frame->height, dec_ctx->pix_fmt,
                                                                                                                                 enc_ctx->width, enc_ctx->height, enc_ctx->pix_fmt,
                                                                                                                                 SWS_BILINEAR, NULL, NULL, NULL);
                                                                                                        
                                                                                                        if (sws_ctx) {
                                                                                                                rgb_frame = av_frame_alloc();
                                                                                                                rgb_frame->format = enc_ctx->pix_fmt;
                                                                                                                rgb_frame->width = enc_ctx->width;
                                                                                                                rgb_frame->height = enc_ctx->height;
                                                                                                                av_frame_get_buffer(rgb_frame, 32);
                                                                                                                
                                                                                                                sws_scale(sws_ctx, (const uint8_t * const*)frame->data, frame->linesize,
                                                                                                                          0, frame->height, rgb_frame->data, rgb_frame->linesize);
                                                                                                                          
                                                                                                                enc_pkt = av_packet_alloc();
                                                                                                                if (avcodec_send_frame(enc_ctx, rgb_frame) == 0) {
                                                                                                                        if (avcodec_receive_packet(enc_ctx, enc_pkt) == 0) {
                                                                                                                                jpeg_data = malloc((size_t)enc_pkt->size);
                                                                                                                                memcpy(jpeg_data, enc_pkt->data, (size_t)enc_pkt->size);
                                                                                                                                jpeg_size = enc_pkt->size;
                                                                                                                        }
                                                                                                                }
                                                                                                                av_packet_free(&enc_pkt);
                                                                                                                av_frame_free(&rgb_frame);
                                                                                                                sws_freeContext(sws_ctx);
                                                                                                        }
                                                                                                }
                                                                                                avcodec_free_context(&enc_ctx);
                                                                                        }
                                                                                        av_packet_unref(pkt);
                                                                                        break;
                                                                                }
                                                                        }
                                                                }
                                                                av_packet_unref(pkt);
                                                        }
                                                        av_packet_free(&pkt);
                                                        av_frame_free(&frame);
                                                }
                                                avcodec_free_context(&dec_ctx);
                                        }
                                }
                        }
                        avformat_close_input(&fmt_ctx);
                }
                
                pthread_mutex_lock(&vhd->lock);
                
                struct thumb_cache *c = malloc(sizeof(*c));
                strncpy(c->filename, t->filename, sizeof(c->filename));
                c->data = jpeg_data;
                c->len = (size_t)jpeg_size;
                
                c->next = vhd->cache_head;
                vhd->cache_head = c;
                vhd->cache_count++;
                
                if (vhd->cache_count > 20) {
                        struct thumb_cache *prev = NULL;
                        struct thumb_cache *curr = vhd->cache_head;
                        while (curr && curr->next) {
                                prev = curr;
                                curr = curr->next;
                        }
                        if (prev) {
                                prev->next = NULL;
                                if (curr->data) free(curr->data);
                                free(curr);
                                vhd->cache_count--;
                        }
                }
                
                pthread_mutex_unlock(&vhd->lock);
                free(t);
                
                lws_cancel_service(vhd->context);
        }
        
        return NULL;
}

int
lws_hls_serve_thumbnail(struct lws *wsi, const char *media_dir, const char *filename)
{
        struct per_vhost_data__lws_hls *vhd = (struct per_vhost_data__lws_hls *)
                lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
        struct per_session_data__lws_hls *pss = (struct per_session_data__lws_hls *)
                lws_wsi_user(wsi);

        if (!vhd || !pss) return -1;

        pthread_mutex_lock(&vhd->lock);
        
        struct thumb_cache *c = vhd->cache_head;
        while (c) {
                if (!strcmp(c->filename, filename))
                        break;
                c = c->next;
        }
        
        if (c) {
                pthread_mutex_unlock(&vhd->lock);
                strncpy(pss->thumb_filename, filename, sizeof(pss->thumb_filename));
                pss->waiting_for_thumbnail = 1;
                lws_callback_on_writable(wsi);
                return 0; 
        }
        
        struct thumb_task *t = vhd->task_head;
        int already_queued = 0;
        while (t) {
                if (!strcmp(t->filename, filename)) {
                        already_queued = 1;
                        break;
                }
                t = t->next;
        }
        
        if (!already_queued) {
                struct thumb_task *nt = malloc(sizeof(*nt));
                if (!nt) {
                        pthread_mutex_unlock(&vhd->lock);
                        return -1;
                }
                strncpy(nt->filename, filename, sizeof(nt->filename));
                nt->next = NULL;
                
                if (vhd->task_tail)
                        vhd->task_tail->next = nt;
                else
                        vhd->task_head = nt;
                vhd->task_tail = nt;
                
                pthread_cond_signal(&vhd->cond);
        }
        
        pthread_mutex_unlock(&vhd->lock);
        
        strncpy(pss->thumb_filename, filename, sizeof(pss->thumb_filename));
        pss->waiting_for_thumbnail = 1;
        lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 30);
        
        return 0;
}


/* Custom AVIOContext writer for memory */
struct hls_buffer {
        uint8_t *ptr;
        size_t size;
        size_t allocated;
};

#if LIBAVFORMAT_VERSION_MAJOR >= 61
static int write_packet(void *opaque, const uint8_t *buf, int buf_size) {
#else
static int write_packet(void *opaque, uint8_t *buf, int buf_size) {
#endif
        struct hls_buffer *hb = (struct hls_buffer *)opaque;
        if (hb->size + (size_t)buf_size > hb->allocated) {
                hb->allocated = (hb->size + (size_t)buf_size) * 2;
                hb->ptr = realloc(hb->ptr, hb->allocated);
        }
        memcpy(hb->ptr + hb->size, buf, (size_t)buf_size);
        hb->size += (size_t)buf_size;
        return buf_size;
}

static size_t find_moof_offset(uint8_t *buf, size_t size) {
    size_t offset = 0;
    while (offset + 8 <= size) {
        uint32_t box_size = (buf[offset] << 24) | (buf[offset+1] << 16) | (buf[offset+2] << 8) | buf[offset+3];
        if (box_size == 1 || box_size < 8) break;
        if (memcmp(buf + offset + 4, "moof", 4) == 0) {
            return offset;
        }
        offset += box_size;
    }
    return 0;
}

int
lws_hls_serve_init(struct lws *wsi, const char *media_dir, const char *filename)
{
        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s/%s", media_dir, filename);

        AVFormatContext *in_ctx = NULL;
        if (avformat_open_input(&in_ctx, filepath, NULL, NULL) < 0) {
                lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, "File not found");
                return -1;
        }

        if (avformat_find_stream_info(in_ctx, NULL) < 0) {
                avformat_close_input(&in_ctx);
                lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Stream info error");
                return -1;
        }

        AVFormatContext *out_ctx = NULL;
        avformat_alloc_output_context2(&out_ctx, NULL, "mp4", NULL);
        if (!out_ctx) {
                avformat_close_input(&in_ctx);
                lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Out ctx error");
                return -1;
        }

        for (unsigned int i = 0; i < in_ctx->nb_streams; i++) {
                AVStream *in_stream = in_ctx->streams[i];
                AVCodecParameters *in_codecpar = in_stream->codecpar;

                if (in_codecpar->codec_type != AVMEDIA_TYPE_VIDEO &&
                    in_codecpar->codec_type != AVMEDIA_TYPE_AUDIO) {
                        continue;
                }

                AVStream *out_stream = avformat_new_stream(out_ctx, NULL);
                avcodec_parameters_copy(out_stream->codecpar, in_codecpar);
                out_stream->codecpar->codec_tag = 0;
                out_stream->time_base = in_stream->time_base;
        }

        struct hls_buffer hb;
        hb.size = 0;
        hb.allocated = 1024 * 1024;
        hb.ptr = malloc(hb.allocated);

        unsigned char *avio_ctx_buffer = av_malloc(32768);
        AVIOContext *avio_ctx = avio_alloc_context(avio_ctx_buffer, 32768, 1, &hb, NULL, write_packet, NULL);
        out_ctx->pb = avio_ctx;

        AVDictionary *opts = NULL;
        av_dict_set(&opts, "movflags", "empty_moov+default_base_moof+delay_moov", 0);

        char timescale_str[32];
        for (unsigned int i = 0; i < out_ctx->nb_streams; i++) {
                if (out_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
                        snprintf(timescale_str, sizeof(timescale_str), "%d", out_ctx->streams[i]->time_base.den);
                        av_dict_set(&opts, "video_track_timescale", timescale_str, 0);
                        break;
                }
        }

        if (avformat_write_header(out_ctx, &opts) < 0) {
                av_dict_free(&opts);
                if (out_ctx) {
                        av_free(out_ctx->pb->buffer);
                        av_free(out_ctx->pb);
                        avformat_free_context(out_ctx);
                }
                avformat_close_input(&in_ctx);
                free(hb.ptr);
                return -1;
        }
        av_write_trailer(out_ctx);
        av_dict_free(&opts);

        if (out_ctx) {
                av_free(out_ctx->pb->buffer);
                av_free(out_ctx->pb);
                avformat_free_context(out_ctx);
        }
        avformat_close_input(&in_ctx);

        struct per_session_data__lws_hls *pss = (struct per_session_data__lws_hls *)lws_wsi_user(wsi);
        if (!pss || hb.size == 0) {
                free(hb.ptr);
                return -1;
        }

        /*
         * The init segment (EXT-X-MAP) must contain ftyp + moov only.
         * If av_write_trailer produced a trailing moof+mdat, strip it.
         * For init: send everything BEFORE the moof.
         * (For media segments the opposite is done: send moof onwards.)
         */
        size_t moof_off = find_moof_offset(hb.ptr, hb.size);
        size_t send_size = moof_off > 0 ? moof_off : hb.size;

        lwsl_user("HLS: Init segment: total=%zu, moof_offset=%zu, "
                  "sending=%zu (ftyp+moov)\n", hb.size, moof_off, send_size);

        pss->segment_buf = malloc(LWS_PRE + send_size);
        if (!pss->segment_buf) {
                free(hb.ptr);
                return -1;
        }

        memcpy(pss->segment_buf + LWS_PRE, hb.ptr, send_size);
        pss->segment_len = send_size;

        pss->segment_pos = 0;
        free(hb.ptr);

        uint8_t hbuf[LWS_PRE + 2048], *start = hbuf + LWS_PRE, *p = start, *end = p + 2048;
        if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "video/mp4",
                                        (lws_filepos_t)pss->segment_len, &p, end) ||
            lws_finalize_write_http_header(wsi, start, &p, end)) {
                return -1;
        }

        lws_callback_on_writable(wsi);
        return 0;
}
int
lws_hls_serve_manifest(struct lws *wsi, const char *media_dir, const char *filename)
{
	char filepath[1024];
	snprintf(filepath, sizeof(filepath), "%s/%s", media_dir, filename);

	AVFormatContext *fmt_ctx = NULL;
	if (avformat_open_input(&fmt_ctx, filepath, NULL, NULL) < 0) {
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, "File not found");
		return -1;
	}

	if (avformat_find_stream_info(fmt_ctx, NULL) < 0) {
		avformat_close_input(&fmt_ctx);
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Stream info error");
		return -1;
	}

	int video_idx = -1;
	unsigned int i_stream;
	int total_segments;

	for (i_stream = 0; i_stream < fmt_ctx->nb_streams; i_stream++) {
		if (fmt_ctx->streams[i_stream]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
			video_idx = (int)i_stream;
			break;
		}
	}

	int64_t duration = fmt_ctx->duration;
	if (duration <= 0 && video_idx >= 0 && fmt_ctx->streams[video_idx]->duration > 0) {
		duration = av_rescale_q(fmt_ctx->streams[video_idx]->duration,
					fmt_ctx->streams[video_idx]->time_base, AV_TIME_BASE_Q);
	}
	
	if (duration <= 0) {
		avformat_close_input(&fmt_ctx);
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Unknown duration");
		return -1;
	}

	total_segments = (int)(duration / ((int64_t)HLS_SEGMENT_DUR * AV_TIME_BASE));
	if (duration % ((int64_t)HLS_SEGMENT_DUR * AV_TIME_BASE) != 0)
		total_segments++;

	avformat_close_input(&fmt_ctx);

	int target_duration = HLS_SEGMENT_DUR;
	size_t m3u8_max = 1024 + (size_t)(total_segments * 128);
	char *m3u8 = malloc(LWS_PRE + m3u8_max);
	if (!m3u8) {
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "OOM");
		return -1;
	}

	char *p_m3u8 = m3u8 + LWS_PRE;
	p_m3u8 += snprintf(p_m3u8, m3u8_max,
		"#EXTM3U\n"
		"#EXT-X-VERSION:7\n"
		"#EXT-X-TARGETDURATION:%d\n"
		"#EXT-X-MEDIA-SEQUENCE:0\n"
		"#EXT-X-MAP:URI=\"../init/%s\"\n"
		"#EXT-X-PLAYLIST-TYPE:VOD\n", target_duration, filename);

	for (int i = 0; i < total_segments; i++) {
		double dur = (double)HLS_SEGMENT_DUR;
		if (i == total_segments - 1) {
			int64_t rem = duration - (int64_t)i * HLS_SEGMENT_DUR * AV_TIME_BASE;
			dur = (double)rem / AV_TIME_BASE;
		}
		if (dur <= 0.0) {
			dur = 0.1;
		}
		size_t rem_buf = m3u8_max - (size_t)(p_m3u8 - (m3u8 + LWS_PRE));
		p_m3u8 += snprintf(p_m3u8, rem_buf,
			"#EXTINF:%f,\n"
			"../segment/%s/%d\n",
			dur, filename, i);
	}

	size_t rem = m3u8_max - (size_t)(p_m3u8 - (m3u8 + LWS_PRE));
	snprintf(p_m3u8, rem, "#EXT-X-ENDLIST\n");
	
	size_t len = strlen(m3u8 + LWS_PRE);

	/* Write out to LWS */
	uint8_t *buf = malloc(LWS_PRE + 2048);
	if (!buf) {
		free(m3u8);
		return -1;
	}

	uint8_t *start = buf + LWS_PRE;
	uint8_t *p = start;
	uint8_t *end = p + 2048;
	
	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/vnd.apple.mpegurl",
					(lws_filepos_t)len, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end)) {
		free(buf);
		free(m3u8);
		return 1;
	}
	
	lws_write(wsi, (uint8_t *)(m3u8 + LWS_PRE), len, LWS_WRITE_HTTP_FINAL);
	
	free(buf);
	free(m3u8);
	return 1; /* Close connection after sending manifest */
}


int
lws_hls_serve_segment(struct lws *wsi, const char *media_dir, const char *filename, int segment_idx)
{
	char filepath[1024];
	snprintf(filepath, sizeof(filepath), "%s/%s", media_dir, filename);

	AVFormatContext *in_ctx = NULL;
	if (avformat_open_input(&in_ctx, filepath, NULL, NULL) < 0) {
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, "File not found");
		return -1;
	}

	if (avformat_find_stream_info(in_ctx, NULL) < 0) {
		avformat_close_input(&in_ctx);
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Stream info error");
		return -1;
	}

	AVFormatContext *out_ctx = NULL;
	avformat_alloc_output_context2(&out_ctx, NULL, "mp4", NULL);
	if (!out_ctx) {
		avformat_close_input(&in_ctx);
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Out ctx error");
		return -1;
	}

	int *stream_mapping = malloc((size_t)in_ctx->nb_streams * sizeof(int));
	int stream_index = 0;
	int has_video = 0;
	int video_idx = -1;
	int audio_idx = -1;
	
	for (unsigned int i = 0; i < in_ctx->nb_streams; i++) {
		AVStream *in_stream = in_ctx->streams[i];
		AVCodecParameters *in_codecpar = in_stream->codecpar;

		if (in_codecpar->codec_type != AVMEDIA_TYPE_VIDEO &&
		    in_codecpar->codec_type != AVMEDIA_TYPE_AUDIO) {
			stream_mapping[i] = -1;
			continue;
		}

		if (in_codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
			has_video = 1;
			video_idx = (int)i;
		}
		if (in_codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
			audio_idx = (int)i;
		}

		stream_mapping[i] = stream_index++;
		AVStream *out_stream = avformat_new_stream(out_ctx, NULL);
		avcodec_parameters_copy(out_stream->codecpar, in_codecpar);
		out_stream->codecpar->codec_tag = 0;
		out_stream->time_base = in_stream->time_base;
	}

	struct hls_buffer hb;
	hb.size = 0;
	hb.allocated = 1024 * 1024; /* 1MB init */
	hb.ptr = malloc(hb.allocated);

	unsigned char *avio_ctx_buffer = av_malloc(32768);
	AVIOContext *avio_ctx = avio_alloc_context(avio_ctx_buffer, 32768,
                                                   1, &hb, NULL, write_packet, NULL);
	out_ctx->pb = avio_ctx;

	
        AVDictionary *opts = NULL;
        av_dict_set(&opts, "movflags", "empty_moov+default_base_moof+delay_moov", 0);
        
        /* Set video_track_timescale to match input for accurate TFDT */
        char timescale_str[32];
        for (unsigned int i = 0; i < out_ctx->nb_streams; i++) {
                if (out_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
                        snprintf(timescale_str, sizeof(timescale_str), "%d", out_ctx->streams[i]->time_base.den);
                        av_dict_set(&opts, "video_track_timescale", timescale_str, 0);
                        break;
                }
        }

        if (avformat_write_header(out_ctx, &opts) < 0) {

		/* Error */
		goto done;
	}

	/*
	 * Do NOT set avoid_negative_ts here. Our timestamps are absolute
	 * positions in the media file (always non-negative). The fMP4 muxer
	 * with delay_moov will write the correct tfdt (Track Fragment Decode
	 * Time) reflecting the absolute position, which hls.js needs to
	 * stitch segments seamlessly without gaps.
	 */

	int64_t start_time = (int64_t)segment_idx * HLS_SEGMENT_DUR * AV_TIME_BASE;
	int64_t end_time = (int64_t)(segment_idx + 1) * HLS_SEGMENT_DUR * AV_TIME_BASE;

	int64_t duration = in_ctx->duration;
	if (duration <= 0 && video_idx >= 0 && in_ctx->streams[video_idx]->duration > 0) {
		duration = av_rescale_q(in_ctx->streams[video_idx]->duration,
					in_ctx->streams[video_idx]->time_base, AV_TIME_BASE_Q);
	}
	
	if (duration > 0 && start_time >= duration) {
		goto done;
	}
	
	lwsl_user("HLS: Segment %d requested. start_time=%lld (%.3fs), end_time=%lld (%.3fs)\n",
		  segment_idx, (long long)start_time, (double)start_time / AV_TIME_BASE,
		  (long long)end_time, (double)end_time / AV_TIME_BASE);

	if (video_idx >= 0) {
		int64_t seek_time = start_time > 5000 ? start_time - 5000 : 0;
		int64_t target_ts = av_rescale_q(seek_time, AV_TIME_BASE_Q, in_ctx->streams[video_idx]->time_base);
		av_seek_frame(in_ctx, video_idx, target_ts, AVSEEK_FLAG_BACKWARD);
		lwsl_user("HLS: Segment %d video seek requested to %lld (%.3fs)\n",
			  segment_idx, (long long)target_ts, (double)start_time / AV_TIME_BASE);
	} else {
		av_seek_frame(in_ctx, -1, start_time, AVSEEK_FLAG_BACKWARD);
		lwsl_user("HLS: Segment %d generic seek requested to %.3fs\n",
			  segment_idx, (double)start_time / AV_TIME_BASE);
	}

	int64_t last_dts[32];
	for (int i = 0; i < 32; i++) {
		last_dts[i] = AV_NOPTS_VALUE;
	}
	int started = 0;
	int video_finished = 0;

	/* Diagnostics variables */
	int64_t first_video_pts = AV_NOPTS_VALUE, last_video_pts = AV_NOPTS_VALUE;
	int64_t first_video_dts = AV_NOPTS_VALUE, last_video_dts = AV_NOPTS_VALUE;
	int64_t first_audio_pts = AV_NOPTS_VALUE, last_audio_pts = AV_NOPTS_VALUE;
	int64_t first_audio_dts = AV_NOPTS_VALUE, last_audio_dts = AV_NOPTS_VALUE;
	int video_packets_written = 0, audio_packets_written = 0;
	int video_packets_discarded = 0, audio_packets_discarded = 0;
	AVRational video_out_time_base = {0, 0};
	AVRational audio_out_time_base = {0, 0};

	AVPacket pkt;
	while (av_read_frame(in_ctx, &pkt) >= 0) {		AVStream *in_stream  = in_ctx->streams[pkt.stream_index];
		if (stream_mapping[pkt.stream_index] < 0) {
			av_packet_unref(&pkt);
			continue;
		}
		/*
		 * Synthesize missing DTS/PTS (MKV has no DTS).
		 * Must happen before boundary checks.
		 */
		if (pkt.dts == AV_NOPTS_VALUE) pkt.dts = pkt.pts;
		if (pkt.pts == AV_NOPTS_VALUE) pkt.pts = pkt.dts;

		/* Use PTS for boundary checks (always valid after synthesis) */
		int64_t pkt_ts = pkt.pts != AV_NOPTS_VALUE ? pkt.pts : pkt.dts;
		if (pkt_ts != AV_NOPTS_VALUE) {
			int64_t pkt_time = av_rescale_q(pkt_ts, in_stream->time_base, AV_TIME_BASE_Q);



			if (!started) {
				if (has_video) {
					if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
						if ((pkt.flags & AV_PKT_FLAG_KEY) && pkt_time >= start_time - 5000) {
							started = 1;
							lwsl_user("HLS: Segment %d started writing video at pkt_time=%.3fs (pts=%lld, dts=%lld)\n",
								  segment_idx, (double)pkt_time / AV_TIME_BASE, (long long)pkt.pts, (long long)pkt.dts);
						} else {
							video_packets_discarded++;
							av_packet_unref(&pkt);
							continue;
						}
					} else {
						/* Audio: discard until video has started */
						if (!started) {
							audio_packets_discarded++;
							av_packet_unref(&pkt);
							continue;
						}
					}
				} else {
					if (pkt_time >= start_time - 5000) {
						started = 1;
						lwsl_user("HLS: Segment %d started writing audio-only at pkt_time=%.3fs (pts=%lld, dts=%lld)\n",
							  segment_idx, (double)pkt_time / AV_TIME_BASE, (long long)pkt.pts, (long long)pkt.dts);
					} else {
						audio_packets_discarded++;
						av_packet_unref(&pkt);
						continue;
					}
				}
			}

			/* Stop at end of segment on next video keyframe */
			if (pkt_time >= end_time - 5000 && in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
				if (pkt.flags & AV_PKT_FLAG_KEY) {
					lwsl_user("HLS: Segment %d reached next video keyframe at pkt_time=%.3fs (pts=%lld, dts=%lld). Video finished.\n",
						  segment_idx, (double)pkt_time / AV_TIME_BASE, (long long)pkt.pts, (long long)pkt.dts);
					video_finished = 1;
					end_time = pkt_time; /* Extend or shrink end_time to match ACTUAL video end */
					av_packet_unref(&pkt);
					continue;
				}
			}

			/* If there's no audio track, we must break once we're sure no more B-frames exist */
			if (video_finished && audio_idx < 0) {
				int64_t dts_time = av_rescale_q(pkt.dts != AV_NOPTS_VALUE ? pkt.dts : pkt.pts, in_stream->time_base, AV_TIME_BASE_Q);
				if (dts_time >= end_time) {
					av_packet_unref(&pkt);
					break;
				}
			}

			if (video_finished && in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
				if (pkt_time >= end_time) {
					video_packets_discarded++;
					av_packet_unref(&pkt);
					continue;
				}
				/* Otherwise, it's a B-frame belonging to the current segment, keep it! */
			}

			/* Stop audio after video has finished and audio reaches the actual video end boundary */
			if (video_finished && in_stream->codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
				if (pkt_time >= end_time) {
					av_packet_unref(&pkt);
					lwsl_user("HLS: Segment %d reached audio end at pkt_time=%.3fs. Stopping.\n",
						  segment_idx, (double)pkt_time / AV_TIME_BASE);
					break;
				}
			}
		}

		int out_stream_idx = stream_mapping[pkt.stream_index];
		pkt.stream_index = out_stream_idx;
		AVStream *out_stream = out_ctx->streams[out_stream_idx];

		pkt.pts = av_rescale_q_rnd(pkt.pts, in_stream->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
		pkt.dts = av_rescale_q_rnd(pkt.dts, in_stream->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
		pkt.duration = av_rescale_q(pkt.duration, in_stream->time_base, out_stream->time_base);
		pkt.pos = -1;

		if (pkt.dts != AV_NOPTS_VALUE) {
			if (last_dts[out_stream_idx] != AV_NOPTS_VALUE && pkt.dts <= last_dts[out_stream_idx]) {
				pkt.dts = last_dts[out_stream_idx] + 1;
			}
			last_dts[out_stream_idx] = pkt.dts;
		}
		if (pkt.pts != AV_NOPTS_VALUE && pkt.pts < pkt.dts) {
			pkt.pts = pkt.dts;
		}

		/* Track stats for output packets */
		if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
			if (first_video_pts == AV_NOPTS_VALUE) {
				first_video_pts = pkt.pts;
				first_video_dts = pkt.dts;
			}
			last_video_pts = pkt.pts;
			last_video_dts = pkt.dts;
			video_packets_written++;
		} else if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
			if (first_audio_pts == AV_NOPTS_VALUE) {
				first_audio_pts = pkt.pts;
				first_audio_dts = pkt.dts;
			}
			last_audio_pts = pkt.pts;
			last_audio_dts = pkt.dts;
			audio_packets_written++;
		}

		av_interleaved_write_frame(out_ctx, &pkt);
		av_packet_unref(&pkt);
	}
	
	av_write_trailer(out_ctx);
        av_dict_free(&opts);

	if (video_idx >= 0 && stream_mapping[video_idx] >= 0) {
		video_out_time_base = out_ctx->streams[stream_mapping[video_idx]]->time_base;
	}
	if (audio_idx >= 0 && stream_mapping[audio_idx] >= 0) {
		audio_out_time_base = out_ctx->streams[stream_mapping[audio_idx]]->time_base;
	}

done:
	if (out_ctx) {
		av_free(out_ctx->pb->buffer);
		av_free(out_ctx->pb);
		avformat_free_context(out_ctx);
	}
	avformat_close_input(&in_ctx);
	free(stream_mapping);

	/* Now we have the segment in hb.ptr! Send it to the client via LWS.
	   For proper LWS async writing, we should save `hb` to per-session data and trigger WRITEABLE.
	   We will allocate the buffer with LWS_PRE, attach to wsi, and request WRITEABLE. */
	
	struct per_session_data__lws_hls *pss = 
		(struct per_session_data__lws_hls *)lws_protocol_vh_priv_get(
			lws_get_vhost(wsi), lws_get_protocol(wsi));
	
	/* Wait, lws_protocol_vh_priv_get gets VHD. We want PSS! */
	pss = (struct per_session_data__lws_hls *)lws_wsi_user(wsi);
	
	if (!pss || hb.size == 0) {
		free(hb.ptr);
		return -1;
	}
	
	
        size_t offset = find_moof_offset(hb.ptr, hb.size);
        size_t send_size = hb.size - offset;

	/* Calculate and log stats */
	double video_duration_sec = 0.0;
	double audio_duration_sec = 0.0;
	double start_av_delta_sec = 0.0;
	double end_av_delta_sec = 0.0;

	if (first_video_pts != AV_NOPTS_VALUE && video_out_time_base.den > 0) {
		video_duration_sec = (double)(last_video_pts - first_video_pts) * av_q2d(video_out_time_base);
	}
	if (first_audio_pts != AV_NOPTS_VALUE && audio_out_time_base.den > 0) {
		audio_duration_sec = (double)(last_audio_pts - first_audio_pts) * av_q2d(audio_out_time_base);
	}
	if (first_video_pts != AV_NOPTS_VALUE && video_out_time_base.den > 0 &&
	    first_audio_pts != AV_NOPTS_VALUE && audio_out_time_base.den > 0) {
		double first_v_sec = (double)first_video_pts * av_q2d(video_out_time_base);
		double first_a_sec = (double)first_audio_pts * av_q2d(audio_out_time_base);
		double last_v_sec = (double)last_video_pts * av_q2d(video_out_time_base);
		double last_a_sec = (double)last_audio_pts * av_q2d(audio_out_time_base);
		start_av_delta_sec = first_a_sec - first_v_sec;
		end_av_delta_sec = last_a_sec - last_v_sec;
	}

	lwsl_user("HLS: Segment %d summary:\n"
		  "  Discarded: video=%d, audio=%d\n"
		  "  Written: video=%d, audio=%d\n"
		  "  Video output PTS: [%lld to %lld] (diff = %lld, %.3fs)\n"
		  "  Video output DTS: [%lld to %lld]\n"
		  "  Audio output PTS: [%lld to %lld] (diff = %lld, %.3fs)\n"
		  "  Audio output DTS: [%lld to %lld]\n"
		  "  First Audio-Video PTS delta: %.3fs\n"
		  "  Last Audio-Video PTS delta: %.3fs\n"
		  "  Segment size: %zu bytes (sent %zu bytes)\n",
		  segment_idx,
		  video_packets_discarded, audio_packets_discarded,
		  video_packets_written, audio_packets_written,
		  (long long)first_video_pts, (long long)last_video_pts,
		  (long long)(last_video_pts - first_video_pts),
		  video_duration_sec,
		  (long long)first_video_dts, (long long)last_video_dts,
		  (long long)first_audio_pts, (long long)last_audio_pts,
		  (long long)(last_audio_pts - first_audio_pts),
		  audio_duration_sec,
		  (long long)first_audio_dts, (long long)last_audio_dts,
		  start_av_delta_sec,
		  end_av_delta_sec,
		  hb.size, send_size);

        pss->segment_buf = malloc(LWS_PRE + send_size);
        if (!pss->segment_buf) {
                free(hb.ptr);
                return -1;
        }

        memcpy(pss->segment_buf + LWS_PRE, hb.ptr + offset, send_size);
        pss->segment_len = send_size;

	pss->segment_pos = 0;
	free(hb.ptr);
	
	/* Send HTTP headers */
	uint8_t hbuf[LWS_PRE + 2048], *start = hbuf + LWS_PRE, *p = start, *end = p + 2048;
	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "video/mp4",
					(lws_filepos_t)pss->segment_len, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end)) {
		return -1;
	}
	
	/* Request writable callback to pump data */
	lws_callback_on_writable(wsi);
	
	return 0; /* Keep connection alive to write data */
}
