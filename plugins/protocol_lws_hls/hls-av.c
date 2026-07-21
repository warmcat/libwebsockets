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
                if (vhd->task_tail == t)
                        vhd->task_tail = NULL;

                strncpy(vhd->current_task_filename, t->filename, sizeof(vhd->current_task_filename));
                vhd->current_task_filename[sizeof(vhd->current_task_filename) - 1] = '\0';
                
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
                                                        
                                                        int64_t target_ts = av_rescale_q(10 * AV_TIME_BASE, AV_TIME_BASE_Q, fmt_ctx->streams[video_idx]->time_base);
                                                        av_seek_frame(fmt_ctx, video_idx, target_ts, AVSEEK_FLAG_BACKWARD);
                                                        
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
                
                vhd->current_task_filename[0] = '\0';

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

struct hls_audio_transcoder {
        AVCodecContext *dec_ctx;
        AVCodecContext *enc_ctx;
        SwrContext *swr_ctx;
        AVAudioFifo *fifo;
        int64_t next_pts;
};

static int needs_audio_transcode(enum AVCodecID codec_id) {
        return codec_id == AV_CODEC_ID_AC3 || codec_id == AV_CODEC_ID_EAC3;
}

static void
free_audio_transcoder(struct hls_audio_transcoder *tx)
{
        if (!tx)
                return;
        if (tx->dec_ctx)
                avcodec_free_context(&tx->dec_ctx);
        if (tx->enc_ctx)
                avcodec_free_context(&tx->enc_ctx);
        if (tx->swr_ctx) {
                swr_free(&tx->swr_ctx);
        }
        if (tx->fifo)
                av_audio_fifo_free(tx->fifo);
        free(tx);
}

static struct hls_audio_transcoder *
init_audio_transcoder(AVFormatContext *in_ctx, int audio_idx)
{
        AVStream *in_stream = in_ctx->streams[audio_idx];
        const AVCodec *decoder = NULL;
        const AVCodec *encoder = NULL;
        struct hls_audio_transcoder *tx = calloc(1, sizeof(*tx));

        if (!tx)
                return NULL;

        decoder = avcodec_find_decoder(in_stream->codecpar->codec_id);
        if (!decoder) {
                lwsl_err("HLS-TRANS: Decoder not found for codec_id %d\n", in_stream->codecpar->codec_id);
                free(tx);
                return NULL;
        }

        tx->dec_ctx = avcodec_alloc_context3(decoder);
        if (!tx->dec_ctx) {
                free(tx);
                return NULL;
        }

        if (avcodec_parameters_to_context(tx->dec_ctx, in_stream->codecpar) < 0) {
                free_audio_transcoder(tx);
                return NULL;
        }

        tx->dec_ctx->thread_count = 1;

        if (avcodec_open2(tx->dec_ctx, decoder, NULL) < 0) {
                free_audio_transcoder(tx);
                return NULL;
        }

        encoder = avcodec_find_encoder(AV_CODEC_ID_AAC);
        if (!encoder) {
                lwsl_err("HLS-TRANS: AAC encoder not found\n");
                free_audio_transcoder(tx);
                return NULL;
        }

        tx->enc_ctx = avcodec_alloc_context3(encoder);
        if (!tx->enc_ctx) {
                free_audio_transcoder(tx);
                return NULL;
        }

        tx->enc_ctx->codec_type = AVMEDIA_TYPE_AUDIO;
        tx->enc_ctx->codec_id = AV_CODEC_ID_AAC;
        tx->enc_ctx->sample_rate = tx->dec_ctx->sample_rate;
        tx->enc_ctx->sample_fmt = AV_SAMPLE_FMT_FLTP;
        tx->enc_ctx->bit_rate = 128000;
        tx->enc_ctx->time_base = (AVRational){1, tx->enc_ctx->sample_rate};

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
        av_channel_layout_default(&tx->enc_ctx->ch_layout, 2);
#else
        tx->enc_ctx->channels = 2;
        tx->enc_ctx->channel_layout = AV_CH_LAYOUT_STEREO;
#endif

        tx->enc_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

        if (avcodec_open2(tx->enc_ctx, encoder, NULL) < 0) {
                lwsl_err("HLS-TRANS: Failed to open AAC encoder\n");
                free_audio_transcoder(tx);
                return NULL;
        }

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
        swr_alloc_set_opts2(&tx->swr_ctx,
                            &tx->enc_ctx->ch_layout, tx->enc_ctx->sample_fmt, tx->enc_ctx->sample_rate,
                            &tx->dec_ctx->ch_layout, tx->dec_ctx->sample_fmt, tx->dec_ctx->sample_rate,
                            0, NULL);
#else
        tx->swr_ctx = swr_alloc_set_opts(NULL,
                                         tx->enc_ctx->channel_layout, tx->enc_ctx->sample_fmt, tx->enc_ctx->sample_rate,
                                         tx->dec_ctx->channel_layout, tx->dec_ctx->sample_fmt, tx->dec_ctx->sample_rate,
                                         0, NULL);
#endif
        if (!tx->swr_ctx || swr_init(tx->swr_ctx) < 0) {
                lwsl_err("HLS-TRANS: SwrContext init failed\n");
                free_audio_transcoder(tx);
                return NULL;
        }

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
        int channels = tx->enc_ctx->ch_layout.nb_channels;
#else
        int channels = tx->enc_ctx->channels;
#endif
        tx->fifo = av_audio_fifo_alloc(tx->enc_ctx->sample_fmt, channels, 10240);
        if (!tx->fifo) {
                lwsl_err("HLS-TRANS: FIFO allocation failed\n");
                free_audio_transcoder(tx);
                return NULL;
        }

        tx->next_pts = 0;

        return tx;
}

static void
transcode_audio_packet(AVFormatContext *in_ctx, AVFormatContext *out_ctx,
                       struct hls_audio_transcoder *audio_tx, AVPacket *pkt,
                       int out_stream_idx, int64_t shift_offset_out_audio,
                       int64_t *first_audio_pts, int64_t *first_audio_dts,
                       int64_t *last_audio_pts, int64_t *last_audio_dts,
                       int *audio_packets_written, int64_t *last_dts,
                       int segment_idx)
{
        AVStream *in_stream = in_ctx->streams[pkt->stream_index];
        int ret;

        /* Set next_pts baseline on first packet */
        if (audio_tx->next_pts == 0) {
                audio_tx->next_pts = av_rescale_q(pkt->pts, in_stream->time_base, audio_tx->enc_ctx->time_base) + shift_offset_out_audio;
        }

        ret = avcodec_send_packet(audio_tx->dec_ctx, pkt);
        if (ret < 0) {
                lwsl_err("HLS-TRANS: Error sending packet to decoder: %d\n", ret);
                return;
        }

        AVFrame *frame = av_frame_alloc();
        AVFrame *resampled_frame = av_frame_alloc();

        while (avcodec_receive_frame(audio_tx->dec_ctx, frame) >= 0) {
                resampled_frame->sample_rate = audio_tx->enc_ctx->sample_rate;
                resampled_frame->format = audio_tx->enc_ctx->sample_fmt;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
                av_channel_layout_copy(&resampled_frame->ch_layout, &audio_tx->enc_ctx->ch_layout);
#else
                resampled_frame->channel_layout = audio_tx->enc_ctx->channel_layout;
                resampled_frame->channels = audio_tx->enc_ctx->channels;
#endif
                resampled_frame->nb_samples = frame->nb_samples;

                ret = av_frame_get_buffer(resampled_frame, 0);
                if (ret >= 0) {
                        ret = swr_convert(audio_tx->swr_ctx,
                                          resampled_frame->data, resampled_frame->nb_samples,
                                          (const uint8_t **)frame->data, frame->nb_samples);
                        if (ret > 0) {
                                resampled_frame->nb_samples = ret;
                                av_audio_fifo_write(audio_tx->fifo, (void **)resampled_frame->data, resampled_frame->nb_samples);
                        }
                }
                av_frame_unref(resampled_frame);
                av_frame_unref(frame);
        }

        av_frame_free(&resampled_frame);
        av_frame_free(&frame);

        int frame_size = audio_tx->enc_ctx->frame_size;
        if (frame_size <= 0) frame_size = 1024;

        while (av_audio_fifo_size(audio_tx->fifo) >= frame_size) {
                AVFrame *enc_frame = av_frame_alloc();
                enc_frame->nb_samples = frame_size;
                enc_frame->format = audio_tx->enc_ctx->sample_fmt;
                enc_frame->sample_rate = audio_tx->enc_ctx->sample_rate;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
                av_channel_layout_copy(&enc_frame->ch_layout, &audio_tx->enc_ctx->ch_layout);
#else
                enc_frame->channel_layout = audio_tx->enc_ctx->channel_layout;
                enc_frame->channels = audio_tx->enc_ctx->channels;
#endif

                ret = av_frame_get_buffer(enc_frame, 0);
                if (ret < 0) {
                        av_frame_free(&enc_frame);
                        break;
                }

                ret = av_audio_fifo_read(audio_tx->fifo, (void **)enc_frame->data, frame_size);
                if (ret < 0) {
                        av_frame_free(&enc_frame);
                        break;
                }

                enc_frame->pts = audio_tx->next_pts;
                audio_tx->next_pts += frame_size;

                ret = avcodec_send_frame(audio_tx->enc_ctx, enc_frame);
                av_frame_free(&enc_frame);
                if (ret < 0) {
                        break;
                }

                AVPacket *enc_pkt = av_packet_alloc();
                while (avcodec_receive_packet(audio_tx->enc_ctx, enc_pkt) >= 0) {
                        enc_pkt->stream_index = out_stream_idx;
                        av_packet_rescale_ts(enc_pkt, audio_tx->enc_ctx->time_base, out_ctx->streams[out_stream_idx]->time_base);

                        if (*first_audio_pts == AV_NOPTS_VALUE) {
                                *first_audio_pts = enc_pkt->pts;
                                *first_audio_dts = enc_pkt->dts;
                        }
                        *last_audio_pts = enc_pkt->pts;
                        *last_audio_dts = enc_pkt->dts;
                        (*audio_packets_written)++;

                        if (enc_pkt->dts != AV_NOPTS_VALUE) {
                                if (*last_dts != AV_NOPTS_VALUE && enc_pkt->dts <= *last_dts) {
                                        enc_pkt->dts = *last_dts + 1;
                                }
                                *last_dts = enc_pkt->dts;
                        }
                        if (enc_pkt->pts != AV_NOPTS_VALUE && enc_pkt->pts < enc_pkt->dts) {
                                enc_pkt->pts = enc_pkt->dts;
                        }

                        if (*audio_packets_written <= 15) {
                                lwsl_info("HLS-PKT-DEBUG: Seg %d Transcoded AAC pts=%lld dts=%lld\n",
                                          segment_idx, (long long)enc_pkt->pts, (long long)enc_pkt->dts);
                        }

                        av_interleaved_write_frame(out_ctx, enc_pkt);
                        av_packet_unref(enc_pkt);
                }
                av_packet_free(&enc_pkt);
        }
}

static void
flush_audio_transcoder(AVFormatContext *out_ctx, struct hls_audio_transcoder *audio_tx,
                       int out_stream_idx, int64_t *first_audio_pts, int64_t *first_audio_dts,
                       int64_t *last_audio_pts, int64_t *last_audio_dts,
                       int *audio_packets_written, int64_t *last_dts,
                       int segment_idx)
{
        int ret;

        /* Drain decoder */
        ret = avcodec_send_packet(audio_tx->dec_ctx, NULL);
        if (ret >= 0) {
                AVFrame *frame = av_frame_alloc();
                AVFrame *resampled_frame = av_frame_alloc();

                while (avcodec_receive_frame(audio_tx->dec_ctx, frame) >= 0) {
                        resampled_frame->sample_rate = audio_tx->enc_ctx->sample_rate;
                        resampled_frame->format = audio_tx->enc_ctx->sample_fmt;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
                        av_channel_layout_copy(&resampled_frame->ch_layout, &audio_tx->enc_ctx->ch_layout);
#else
                        resampled_frame->channel_layout = audio_tx->enc_ctx->channel_layout;
                        resampled_frame->channels = audio_tx->enc_ctx->channels;
#endif
                        resampled_frame->nb_samples = frame->nb_samples;

                        ret = av_frame_get_buffer(resampled_frame, 0);
                        if (ret >= 0) {
                                ret = swr_convert(audio_tx->swr_ctx,
                                                  resampled_frame->data, resampled_frame->nb_samples,
                                                  (const uint8_t **)frame->data, frame->nb_samples);
                                if (ret > 0) {
                                        resampled_frame->nb_samples = ret;
                                        av_audio_fifo_write(audio_tx->fifo, (void **)resampled_frame->data, resampled_frame->nb_samples);
                                }
                        }
                        av_frame_unref(resampled_frame);
                        av_frame_unref(frame);
                }
                av_frame_free(&resampled_frame);
                av_frame_free(&frame);
        }

        int frame_size = audio_tx->enc_ctx->frame_size;
        if (frame_size <= 0) frame_size = 1024;

        /* Pad any remaining partial frame in FIFO with silence */
        int extra_samples = av_audio_fifo_size(audio_tx->fifo);
        if (extra_samples > 0) {
                AVFrame *enc_frame = av_frame_alloc();
                enc_frame->nb_samples = frame_size;
                enc_frame->format = audio_tx->enc_ctx->sample_fmt;
                enc_frame->sample_rate = audio_tx->enc_ctx->sample_rate;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
                av_channel_layout_copy(&enc_frame->ch_layout, &audio_tx->enc_ctx->ch_layout);
#else
                enc_frame->channel_layout = audio_tx->enc_ctx->channel_layout;
                enc_frame->channels = audio_tx->enc_ctx->channels;
#endif

                ret = av_frame_get_buffer(enc_frame, 0);
                if (ret >= 0) {
                        int read_samples = extra_samples < frame_size ? extra_samples : frame_size;
                        av_audio_fifo_read(audio_tx->fifo, (void **)enc_frame->data, read_samples);
                        if (read_samples < frame_size) {
                                av_samples_set_silence(enc_frame->data, read_samples, frame_size - read_samples,
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
                                                       enc_frame->ch_layout.nb_channels,
#else
                                                       enc_frame->channels,
#endif
                                                       enc_frame->format);
                        }

                        enc_frame->pts = audio_tx->next_pts;
                        audio_tx->next_pts += frame_size;

                        avcodec_send_frame(audio_tx->enc_ctx, enc_frame);
                }
                av_frame_free(&enc_frame);
        }

        /* Drain encoder */
        avcodec_send_frame(audio_tx->enc_ctx, NULL);

        AVPacket *enc_pkt = av_packet_alloc();
        while (avcodec_receive_packet(audio_tx->enc_ctx, enc_pkt) >= 0) {
                enc_pkt->stream_index = out_stream_idx;
                av_packet_rescale_ts(enc_pkt, audio_tx->enc_ctx->time_base, out_ctx->streams[out_stream_idx]->time_base);

                if (*first_audio_pts == AV_NOPTS_VALUE) {
                        *first_audio_pts = enc_pkt->pts;
                        *first_audio_dts = enc_pkt->dts;
                }
                *last_audio_pts = enc_pkt->pts;
                *last_audio_dts = enc_pkt->dts;
                (*audio_packets_written)++;

                if (enc_pkt->dts != AV_NOPTS_VALUE) {
                        if (*last_dts != AV_NOPTS_VALUE && enc_pkt->dts <= *last_dts) {
                                enc_pkt->dts = *last_dts + 1;
                        }
                        *last_dts = enc_pkt->dts;
                }
                if (enc_pkt->pts != AV_NOPTS_VALUE && enc_pkt->pts < enc_pkt->dts) {
                        enc_pkt->pts = enc_pkt->dts;
                }

                lwsl_info("HLS-PKT-DEBUG: Seg %d Transcoded AAC final flush pts=%lld dts=%lld\n",
                          segment_idx, (long long)enc_pkt->pts, (long long)enc_pkt->dts);

                av_interleaved_write_frame(out_ctx, enc_pkt);
                av_packet_unref(enc_pkt);
        }
        av_packet_free(&enc_pkt);
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
        in_ctx->flags |= AVFMT_FLAG_GENPTS;

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

        int video_idx = -1;
        int audio_idx = -1;
        for (unsigned int i = 0; i < in_ctx->nb_streams; i++) {
                if (in_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
                        if (video_idx < 0) video_idx = (int)i;
                } else if (in_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
                        if (audio_idx < 0 || in_ctx->streams[i]->codecpar->codec_id == AV_CODEC_ID_AAC) {
                                audio_idx = (int)i;
                        }
                }
        }

        if (video_idx >= 0) {
                AVStream *in_stream = in_ctx->streams[video_idx];
                AVStream *out_stream = avformat_new_stream(out_ctx, NULL);
                avcodec_parameters_copy(out_stream->codecpar, in_stream->codecpar);
                if (in_stream->codecpar->codec_id == AV_CODEC_ID_HEVC) {
                        out_stream->codecpar->codec_tag = MKTAG('h', 'v', 'c', '1');
                        if (out_stream->codecpar->extradata && out_stream->codecpar->extradata_size >= 13) {
                                if (out_stream->codecpar->extradata[12] > 120) {
                                        lwsl_notice("HLS-AV: Clamping HEVC level from %d to 120\n",
                                                    out_stream->codecpar->extradata[12]);
                                        out_stream->codecpar->extradata[12] = 120;
                                }
                        }
                } else {
                        out_stream->codecpar->codec_tag = 0;
                }
                out_stream->time_base = (AVRational){1, 90000};
        }
        if (audio_idx >= 0) {
                AVStream *in_stream = in_ctx->streams[audio_idx];
                AVStream *out_stream = avformat_new_stream(out_ctx, NULL);
                if (needs_audio_transcode(in_stream->codecpar->codec_id)) {
                        struct hls_audio_transcoder *tx = init_audio_transcoder(in_ctx, audio_idx);
                        if (tx) {
                                avcodec_parameters_from_context(out_stream->codecpar, tx->enc_ctx);
                                lwsl_notice("HLS-AV: serve_init audio extradata_size=%d\n", out_stream->codecpar->extradata_size);
                                out_stream->codecpar->codec_tag = 0;
                                out_stream->time_base = (AVRational){1, tx->enc_ctx->sample_rate};
                                free_audio_transcoder(tx);
                        } else {
                                avcodec_parameters_copy(out_stream->codecpar, in_stream->codecpar);
                                out_stream->codecpar->codec_tag = 0;
                                out_stream->time_base = in_stream->time_base;
                        }
                } else {
                        avcodec_parameters_copy(out_stream->codecpar, in_stream->codecpar);
                        out_stream->codecpar->codec_tag = 0;
                        out_stream->time_base = in_stream->time_base;
                }
        }

        struct hls_buffer hb;
        hb.size = 0;
        hb.allocated = 1024 * 1024;
        hb.ptr = malloc(hb.allocated);

        unsigned char *avio_ctx_buffer = av_malloc(32768);
        AVIOContext *avio_ctx = avio_alloc_context(avio_ctx_buffer, 32768, 1, &hb, NULL, write_packet, NULL);
        out_ctx->pb = avio_ctx;

        AVDictionary *opts = NULL;
        av_dict_set(&opts, "movflags", "empty_moov+default_base_moof+delay_moov+negative_cts_offsets+frag_discont", 0);
        av_dict_set(&opts, "use_editlist", "0", 0);

        char timescale_str[32];
        for (unsigned int i = 0; i < out_ctx->nb_streams; i++) {
                if (out_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
                        snprintf(timescale_str, sizeof(timescale_str), "%d", out_ctx->streams[i]->time_base.den);
                        av_dict_set(&opts, "video_track_timescale", timescale_str, 0);
                        break;
                }
        }

        out_ctx->avoid_negative_ts = 0;
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

        lwsl_info("HLS: Init segment: total=%zu, moof_offset=%zu, "
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
#if LIBAVFORMAT_VERSION_MAJOR >= 58
#define get_index_count(st) avformat_index_get_entries_count(st)
#define get_index_entry(st, idx) avformat_index_get_entry(st, idx)
#else
#define get_index_count(st) ((st)->nb_index_entries)
#define get_index_entry(st, idx) (&((st)->index_entries[idx]))
#endif

struct hls_segment_info {
	int64_t start_pts;
	int64_t end_pts;
	int64_t seek_pts;
	double duration_sec;
};

static int64_t
get_entry_dts(AVStream *st, const AVIndexEntry *entry)
{
	if (!entry) return 0;
	if (st->codecpar->codec_type == AVMEDIA_TYPE_VIDEO && st->codecpar->video_delay > 0) {
		int64_t frame_dur = st->codecpar->video_delay * 42; /* standard fallback */
		AVRational fps = st->avg_frame_rate.num > 0 ? st->avg_frame_rate : st->r_frame_rate;
		if (fps.num > 0 && fps.den > 0) {
			int64_t single_dur = av_rescale_q(1, av_inv_q(fps), st->time_base);
			if (single_dur > 0) {
				frame_dur = st->codecpar->video_delay * single_dur;
			}
		}
		return entry->timestamp - frame_dur;
	}
	return entry->timestamp;
}

static int
lws_hls_get_segment_info(struct per_vhost_data__lws_hls *vhd, const char *filename,
                         AVFormatContext *in_ctx, int video_idx, int target_seg_idx,
			 struct hls_segment_info *out_info, int *out_total_segments)
{
	AVStream *st = in_ctx->streams[video_idx];
	int count = get_index_count(st);

	/* Check index cache first */
	struct hls_file_index *idx = NULL;
	if (vhd) {
		pthread_mutex_lock(&vhd->lock);
		struct hls_file_index *curr = vhd->index_head;
		while (curr) {
			if (!strcmp(curr->filename, filename) && curr->video_idx == video_idx) {
				idx = curr;
				break;
			}
			curr = curr->next;
		}
		pthread_mutex_unlock(&vhd->lock);
	}

	if (idx) {
		/* Populate index entries from cache if context's index is empty */
		if (count <= 1) {
			for (int i = 0; i < idx->count; i++) {
				av_add_index_entry(st, idx->entries[i].pos, idx->entries[i].timestamp,
						   idx->entries[i].size, idx->entries[i].min_distance,
						   idx->entries[i].flags);
			}
			count = get_index_count(st);
		}
	} else {
		/* Cues load and scan fallback as before */
		if (count <= 1) {
			/* Try to seek to the end once to force Matroska cues loading */
			int64_t seek_target = st->duration > 0 ? st->duration : 
				(in_ctx->duration > 0 ? av_rescale_q(in_ctx->duration, AV_TIME_BASE_Q, st->time_base) : 0);
			if (seek_target > 0) {
				av_seek_frame(in_ctx, video_idx, seek_target, AVSEEK_FLAG_BACKWARD);
			}
			count = get_index_count(st);
		}
		if (count <= 1) {
			/* Fallback: Scan the file once to build index entries */
			lwsl_user("HLS-INDEX: Index missing or empty, scanning file to build index...\n");
			av_seek_frame(in_ctx, video_idx, 0, AVSEEK_FLAG_BACKWARD);
			AVPacket pkt;
			while (av_read_frame(in_ctx, &pkt) >= 0) {
				if (pkt.stream_index == video_idx && (pkt.flags & AV_PKT_FLAG_KEY)) {
					av_add_index_entry(st, pkt.pos, pkt.pts, pkt.size, 0, AVINDEX_KEYFRAME);
				}
				av_packet_unref(&pkt);
			}
			/* Clear EOF flags to restore stream readability */
			if (in_ctx->pb) {
				in_ctx->pb->eof_reached = 0;
				in_ctx->pb->error = 0;
			}
			av_seek_frame(in_ctx, video_idx, 0, AVSEEK_FLAG_BACKWARD);
			count = get_index_count(st);
		}

		/* Save index to cache if successfully built */
		if (vhd && count > 1) {
			struct hls_file_index *new_idx = malloc(sizeof(struct hls_file_index));
			if (new_idx) {
				memset(new_idx, 0, sizeof(*new_idx));
				strncpy(new_idx->filename, filename, sizeof(new_idx->filename) - 1);
				new_idx->video_idx = video_idx;
				new_idx->count = count;
				new_idx->entries = malloc((size_t)count * sizeof(struct hls_index_entry));
				if (new_idx->entries) {
					for (int i = 0; i < count; i++) {
						const AVIndexEntry *entry = get_index_entry(st, i);
						new_idx->entries[i].pos = entry->pos;
						new_idx->entries[i].timestamp = entry->timestamp;
						new_idx->entries[i].min_distance = entry->min_distance;
						new_idx->entries[i].size = entry->size;
						new_idx->entries[i].flags = entry->flags;
						new_idx->entries[i].dts = AV_NOPTS_VALUE;
					}

					/* Now scan the file to retrieve the true DTS for each index entry */
					av_seek_frame(in_ctx, video_idx, 0, AVSEEK_FLAG_BACKWARD);
					AVPacket scan_pkt;
					while (av_read_frame(in_ctx, &scan_pkt) >= 0) {
						if (scan_pkt.stream_index == video_idx && (scan_pkt.flags & AV_PKT_FLAG_KEY)) {
							for (int i = 0; i < count; i++) {
								if (new_idx->entries[i].pos == scan_pkt.pos || new_idx->entries[i].timestamp == scan_pkt.pts) {
									new_idx->entries[i].dts = scan_pkt.dts;
									break;
								}
							}
						}
						av_packet_unref(&scan_pkt);
					}
					if (in_ctx->pb) {
						in_ctx->pb->eof_reached = 0;
						in_ctx->pb->error = 0;
					}
					av_seek_frame(in_ctx, video_idx, 0, AVSEEK_FLAG_BACKWARD);

					pthread_mutex_lock(&vhd->lock);
					new_idx->next = vhd->index_head;
					vhd->index_head = new_idx;
					idx = new_idx;
					pthread_mutex_unlock(&vhd->lock);
				} else {
					free(new_idx);
				}
			}
		}
	}

	lwsl_info("HLS-INDEX-DEBUG: video_idx=%d, count=%d, target_seg_idx=%d, duration=%lld\n",
		  video_idx, count, target_seg_idx, (long long)st->duration);
	if (count <= 0) {
		return -1;
	}

	for (int i = 0; i < count && i < 10; i++) {
		const AVIndexEntry *entry = get_index_entry(st, i);
		if (entry) {
			lwsl_info("HLS-INDEX-DEBUG: entry[%d] timestamp=%lld, flags=0x%x, size=%d, pos=%lld\n",
				  i, (long long)entry->timestamp, entry->flags, entry->size, (long long)entry->pos);
		}
	}

	int current_seg = 0;
	const AVIndexEntry *start_entry = get_index_entry(st, 0);
	int64_t current_start_pts = AV_NOPTS_VALUE;
	if (idx && idx->count > 0 && idx->entries[0].dts != AV_NOPTS_VALUE) {
		current_start_pts = idx->entries[0].dts;
	} else {
		current_start_pts = start_entry ? get_entry_dts(st, start_entry) : 0;
	}
	int64_t last_pts = current_start_pts;
	
	if (out_info && target_seg_idx == 0) {
		out_info->start_pts = current_start_pts;
		out_info->seek_pts = start_entry ? start_entry->timestamp : 0;
	}

	for (int i = 1; i < count; i++) {
		const AVIndexEntry *entry = get_index_entry(st, i);
		if (!entry) continue;
		if (!(entry->flags & AVINDEX_KEYFRAME)) continue;

		int64_t entry_dts = AV_NOPTS_VALUE;
		if (idx && i < idx->count && idx->entries[i].dts != AV_NOPTS_VALUE) {
			entry_dts = idx->entries[i].dts;
		} else {
			entry_dts = get_entry_dts(st, entry);
		}

		double dur = (double)(entry_dts - current_start_pts) * av_q2d(st->time_base);
		if (dur >= (double)HLS_SEGMENT_DUR) {
			if (out_info && current_seg == target_seg_idx) {
				out_info->end_pts = entry_dts;
				out_info->duration_sec = dur;
			}
			current_seg++;
			current_start_pts = entry_dts;
			if (out_info && current_seg == target_seg_idx) {
				out_info->start_pts = current_start_pts;
				out_info->seek_pts = entry->timestamp;
			}
		}
		last_pts = entry_dts;
	}

	int64_t stream_dur = st->duration > 0 ? st->duration : 
		(in_ctx->duration > 0 ? av_rescale_q(in_ctx->duration, AV_TIME_BASE_Q, st->time_base) : last_pts - current_start_pts);
	double final_dur = (double)(stream_dur - current_start_pts) * av_q2d(st->time_base);



	if (target_seg_idx >= 0 && target_seg_idx > current_seg) {
		lwsl_info("HLS-INDEX-DEBUG: target_seg_idx %d > current_seg %d, ret -1\n", target_seg_idx, current_seg);
		return -1;
	}

	if (out_info && current_seg == target_seg_idx) {
		out_info->end_pts = AV_NOPTS_VALUE;
		if (final_dur <= 0.1) final_dur = 0.1;
		out_info->duration_sec = final_dur;
		lwsl_info("HLS-INDEX-DEBUG: target_seg_idx=%d final match -> start_pts=%lld, end_pts=%lld, duration_sec=%.3f\n",
			  target_seg_idx, (long long)out_info->start_pts, (long long)out_info->end_pts, out_info->duration_sec);
	}

	if (out_total_segments) {
		*out_total_segments = current_seg + 1;
	}
	
	lwsl_info("HLS-INDEX-DEBUG: ret=0, total_segments=%d\n", out_total_segments ? *out_total_segments : -1);
	return 0;
}

int
lws_hls_serve_manifest(struct lws *wsi, const char *media_dir, const char *filename)
{
	char filepath[1024];
	snprintf(filepath, sizeof(filepath), "%s/%s", media_dir, filename);

	struct per_vhost_data__lws_hls *vhd =
			(struct per_vhost_data__lws_hls *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));

	AVFormatContext *fmt_ctx = NULL;
	if (avformat_open_input(&fmt_ctx, filepath, NULL, NULL) < 0) {
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, "File not found");
		return -1;
	}
	fmt_ctx->flags |= AVFMT_FLAG_GENPTS;

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

	int has_index = 0;
	if (video_idx >= 0 && lws_hls_get_segment_info(vhd, filename, fmt_ctx, video_idx, -1, NULL, &total_segments) == 0) {
		has_index = 1;
	} else {
		total_segments = (int)(duration / ((int64_t)HLS_SEGMENT_DUR * AV_TIME_BASE));
		if (duration % ((int64_t)HLS_SEGMENT_DUR * AV_TIME_BASE) != 0)
			total_segments++;
	}

	/* We must compute max target duration from index to be standard compliant */
	int target_duration = HLS_SEGMENT_DUR;
	if (has_index) {
		double max_dur = 0;
		for (int i = 0; i < total_segments; i++) {
			struct hls_segment_info sinfo;
			memset(&sinfo, 0, sizeof(sinfo));
			sinfo.end_pts = AV_NOPTS_VALUE;
			if (lws_hls_get_segment_info(vhd, filename, fmt_ctx, video_idx, i, &sinfo, NULL) == 0) {
				if (sinfo.duration_sec > max_dur) max_dur = sinfo.duration_sec;
			}
		}
		target_duration = (int)(max_dur + 0.999); /* round up */
	}

	size_t m3u8_max = 1024 + (size_t)(total_segments * 128);
	char *m3u8 = malloc(LWS_PRE + m3u8_max);
	if (!m3u8) {
		avformat_close_input(&fmt_ctx);
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
		if (has_index) {
			struct hls_segment_info sinfo;
			memset(&sinfo, 0, sizeof(sinfo));
			sinfo.end_pts = AV_NOPTS_VALUE;
			if (lws_hls_get_segment_info(vhd, filename, fmt_ctx, video_idx, i, &sinfo, NULL) == 0) {
				dur = sinfo.duration_sec;
			}
		} else {
			if (i == total_segments - 1) {
				int64_t rem = duration - (int64_t)i * HLS_SEGMENT_DUR * AV_TIME_BASE;
				dur = (double)rem / AV_TIME_BASE;
			}
			if (dur <= 0.0) {
				dur = 0.1;
			}
		}
		size_t rem_buf = m3u8_max - (size_t)(p_m3u8 - (m3u8 + LWS_PRE));
		p_m3u8 += snprintf(p_m3u8, rem_buf,
			"#EXTINF:%f,\n"
			"../segment/%s/%d\n",
			dur, filename, i);
	}

	avformat_close_input(&fmt_ctx);

	size_t rem = m3u8_max - (size_t)(p_m3u8 - (m3u8 + LWS_PRE));
	snprintf(p_m3u8, rem, "#EXT-X-ENDLIST\n");
	
	size_t len = strlen(m3u8 + LWS_PRE);

	struct per_session_data__lws_hls *pss = (struct per_session_data__lws_hls *)lws_wsi_user(wsi);
	if (!pss) {
		free(m3u8);
		return -1;
	}

	pss->segment_buf = malloc(LWS_PRE + len);
	if (!pss->segment_buf) {
		free(m3u8);
		return -1;
	}

	memcpy(pss->segment_buf + LWS_PRE, m3u8 + LWS_PRE, len);
	pss->segment_len = len;
	pss->segment_pos = 0;
	free(m3u8);

	/* Send HTTP headers */
	uint8_t hbuf[LWS_PRE + 2048], *start = hbuf + LWS_PRE, *p = start, *end = p + 2048;
	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/vnd.apple.mpegurl",
					(lws_filepos_t)pss->segment_len, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end)) {
		free(pss->segment_buf);
		pss->segment_buf = NULL;
		return -1;
	}

	/* Request writable callback to pump data in safe chunks */
	lws_callback_on_writable(wsi);
	return 0;
}


int
lws_hls_serve_segment(struct lws *wsi, const char *media_dir, const char *filename, int segment_idx)
{
	char filepath[1024];
	snprintf(filepath, sizeof(filepath), "%s/%s", media_dir, filename);

	struct per_vhost_data__lws_hls *vhd =
			(struct per_vhost_data__lws_hls *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));

	AVFormatContext *in_ctx = NULL;
	if (avformat_open_input(&in_ctx, filepath, NULL, NULL) < 0) {
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, "File not found");
		return -1;
	}
	in_ctx->flags |= AVFMT_FLAG_GENPTS;

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

	struct hls_audio_transcoder *audio_tx = NULL;
	int transcode_audio = 0;

	int *stream_mapping = malloc((size_t)in_ctx->nb_streams * sizeof(int));
	for (unsigned int i = 0; i < in_ctx->nb_streams; i++) {
		stream_mapping[i] = -1;
	}
	int stream_index = 0;
	int has_video = 0;
	int video_idx = -1;
	int audio_idx = -1;
	
	for (unsigned int i = 0; i < in_ctx->nb_streams; i++) {
		if (in_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
			if (video_idx < 0) video_idx = (int)i;
		} else if (in_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
			if (audio_idx < 0 || in_ctx->streams[i]->codecpar->codec_id == AV_CODEC_ID_AAC) {
				audio_idx = (int)i;
			}
		}
	}

	if (video_idx >= 0) {
		has_video = 1;
		stream_mapping[video_idx] = stream_index++;
		AVStream *in_stream = in_ctx->streams[video_idx];
		AVStream *out_stream = avformat_new_stream(out_ctx, NULL);
		avcodec_parameters_copy(out_stream->codecpar, in_stream->codecpar);
		if (in_stream->codecpar->codec_id == AV_CODEC_ID_HEVC) {
			out_stream->codecpar->codec_tag = MKTAG('h', 'v', 'c', '1');
			if (out_stream->codecpar->extradata && out_stream->codecpar->extradata_size >= 13) {
				if (out_stream->codecpar->extradata[12] > 120) {
					out_stream->codecpar->extradata[12] = 120;
				}
			}
		} else {
			out_stream->codecpar->codec_tag = 0;
		}
		out_stream->time_base = (AVRational){1, 90000};
	}
	if (audio_idx >= 0) {
		stream_mapping[audio_idx] = stream_index++;
		AVStream *in_stream = in_ctx->streams[audio_idx];
		AVStream *out_stream = avformat_new_stream(out_ctx, NULL);
		if (needs_audio_transcode(in_stream->codecpar->codec_id)) {
			transcode_audio = 1;
			audio_tx = init_audio_transcoder(in_ctx, audio_idx);
			if (audio_tx) {
				avcodec_parameters_from_context(out_stream->codecpar, audio_tx->enc_ctx);
				out_stream->codecpar->codec_tag = 0;
				out_stream->time_base = (AVRational){1, audio_tx->enc_ctx->sample_rate};
			} else {
				transcode_audio = 0;
				avcodec_parameters_copy(out_stream->codecpar, in_stream->codecpar);
				out_stream->codecpar->codec_tag = 0;
				out_stream->time_base = in_stream->time_base;
			}
		} else {
			avcodec_parameters_copy(out_stream->codecpar, in_stream->codecpar);
			out_stream->codecpar->codec_tag = 0;
			out_stream->time_base = in_stream->time_base;
		}
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
        av_dict_set(&opts, "movflags", "empty_moov+default_base_moof+delay_moov+negative_cts_offsets+frag_discont", 0);
        av_dict_set(&opts, "use_editlist", "0", 0);
        av_dict_set_int(&opts, "fragment_index", segment_idx + 1, 0);
        
        /* Set video_track_timescale to match input for accurate TFDT */
        char timescale_str[32];
        for (unsigned int i = 0; i < out_ctx->nb_streams; i++) {
                if (out_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
                        snprintf(timescale_str, sizeof(timescale_str), "%d", out_ctx->streams[i]->time_base.den);
                        av_dict_set(&opts, "video_track_timescale", timescale_str, 0);
                        break;
                }
        }

        out_ctx->avoid_negative_ts = 0;
        if (avformat_write_header(out_ctx, &opts) < 0) {

		/* Error */
		goto done;
	}

	int64_t shift_offset = 0;
	int64_t shift_offset_out_video = 0;
	int64_t shift_offset_out_audio = 0;
	if (video_idx >= 0) {
		AVStream *vst = in_ctx->streams[video_idx];
		if (get_index_count(vst) > 0) {
			const AVIndexEntry *entry0 = get_index_entry(vst, 0);
			if (entry0) {
				int64_t entry0_dts = get_entry_dts(vst, entry0);
				if (entry0_dts < 0) {
					shift_offset = -entry0_dts;
				}
			}
		}
	}
	if (video_idx >= 0 && shift_offset > 0 && stream_mapping[video_idx] >= 0) {
		shift_offset_out_video = av_rescale_q(shift_offset, in_ctx->streams[video_idx]->time_base, out_ctx->streams[stream_mapping[video_idx]]->time_base);
	}
	if (audio_idx >= 0 && video_idx >= 0 && shift_offset > 0 && stream_mapping[audio_idx] >= 0) {
		shift_offset_out_audio = av_rescale_q(shift_offset, in_ctx->streams[video_idx]->time_base, out_ctx->streams[stream_mapping[audio_idx]]->time_base);
	}

	int64_t start_time = (int64_t)segment_idx * HLS_SEGMENT_DUR * AV_TIME_BASE;
	int64_t end_time = (int64_t)(segment_idx + 1) * HLS_SEGMENT_DUR * AV_TIME_BASE;
	int has_index = 0;
	struct hls_segment_info sinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.end_pts = AV_NOPTS_VALUE;

	if (video_idx >= 0 && lws_hls_get_segment_info(vhd, filename, in_ctx, video_idx, segment_idx, &sinfo, NULL) == 0) {
		has_index = 1;
		start_time = av_rescale_q(sinfo.start_pts, in_ctx->streams[video_idx]->time_base, AV_TIME_BASE_Q);
		if (sinfo.end_pts != AV_NOPTS_VALUE) {
			end_time = av_rescale_q(sinfo.end_pts, in_ctx->streams[video_idx]->time_base, AV_TIME_BASE_Q);
		} else {
			end_time = INT64_MAX; /* Read until EOF */
		}
	}

	int64_t duration = in_ctx->duration;
	if (duration <= 0 && video_idx >= 0 && in_ctx->streams[video_idx]->duration > 0) {
		duration = av_rescale_q(in_ctx->streams[video_idx]->duration,
					in_ctx->streams[video_idx]->time_base, AV_TIME_BASE_Q);
	}
	
	if (!has_index && duration > 0 && start_time >= duration) {
		goto done;
	}
	
	lwsl_info("HLS: Segment %d requested. start_time=%lld (%.3fs), end_time=%lld (%.3fs) [Index: %s]\n",
		  segment_idx, (long long)start_time, (double)start_time / AV_TIME_BASE,
		  (long long)end_time, (double)end_time / AV_TIME_BASE, has_index ? "YES" : "NO");
	lwsl_info("HLS-DEBUG: Serving segment %d. has_index=%d, sinfo.start_pts=%lld, sinfo.end_pts=%lld, start_time=%lld, end_time=%lld\n",
		  segment_idx, has_index, (long long)sinfo.start_pts, (long long)sinfo.end_pts,
		  (long long)start_time, (long long)end_time);

	if (video_idx >= 0 && has_index) {
		int64_t target_ts = sinfo.start_pts;
		int64_t max_ts = sinfo.seek_pts;
		
		int ret = avformat_seek_file(in_ctx, video_idx, target_ts - 500, target_ts, max_ts, AVSEEK_FLAG_FRAME);
		lwsl_info("HLS-DEBUG: Segment %d video seek requested to %lld -> ret=%d\n",
			  segment_idx, (long long)target_ts, ret);
	} else {
		int ret = avformat_seek_file(in_ctx, -1, INT64_MIN, start_time, start_time, 0);
		lwsl_info("HLS: Segment %d generic seek requested to %.3fs -> ret=%d\n",
			  segment_idx, (double)start_time / AV_TIME_BASE, ret);
	}

	int64_t last_dts[32];
	for (int i = 0; i < 32; i++) {
		last_dts[i] = AV_NOPTS_VALUE;
	}
	int started = 0;
	int64_t actual_start_pts = AV_NOPTS_VALUE;
	int video_finished = 0;
	AVPacket audio_buffer[512];
	int audio_buffer_count = 0;
	memset(audio_buffer, 0, sizeof(audio_buffer));

	/* Diagnostics variables */
	int64_t first_video_pts = AV_NOPTS_VALUE, last_video_pts = AV_NOPTS_VALUE;
	int64_t first_video_dts = AV_NOPTS_VALUE, last_video_dts = AV_NOPTS_VALUE;
	int64_t first_audio_pts = AV_NOPTS_VALUE, last_audio_pts = AV_NOPTS_VALUE;
	int64_t first_audio_dts = AV_NOPTS_VALUE, last_audio_dts = AV_NOPTS_VALUE;
	int video_packets_written = 0, audio_packets_written = 0;
	int video_packets_discarded = 0, audio_packets_discarded = 0;
	AVRational video_out_time_base = {0, 0};
	AVRational audio_out_time_base = {0, 0};

	int64_t next_video_dts = AV_NOPTS_VALUE;
	if (has_index) {
		next_video_dts = sinfo.start_pts;
	}

	AVPacket pkt;
	while (av_read_frame(in_ctx, &pkt) >= 0) {
		AVStream *in_stream  = in_ctx->streams[pkt.stream_index];
		if (stream_mapping[pkt.stream_index] < 0) {
			av_packet_unref(&pkt);
			continue;
		}
		/*
		 * Synthesize missing DTS/PTS (MKV has no DTS).
		 * Must happen before boundary checks.
		 */
		if (pkt.dts == AV_NOPTS_VALUE) {
			if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
				int64_t frame_dur = pkt.duration;
				if (frame_dur <= 0) {
					AVRational fps = in_stream->avg_frame_rate.num > 0 ? in_stream->avg_frame_rate : in_stream->r_frame_rate;
					if (fps.num > 0 && fps.den > 0) {
						frame_dur = av_rescale_q(1, av_inv_q(fps), in_stream->time_base);
					}
				}
				if (frame_dur <= 0) {
					frame_dur = av_rescale_q(1, (AVRational){1, 24}, in_stream->time_base);
				}
				if (next_video_dts == AV_NOPTS_VALUE) {
					next_video_dts = pkt.pts - in_stream->codecpar->video_delay * frame_dur;
				}
				pkt.dts = next_video_dts;
				next_video_dts += frame_dur;
			} else {
				pkt.dts = pkt.pts;
			}
		} else if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
			int64_t frame_dur = pkt.duration;
			if (frame_dur <= 0) {
				AVRational fps = in_stream->avg_frame_rate.num > 0 ? in_stream->avg_frame_rate : in_stream->r_frame_rate;
				if (fps.num > 0 && fps.den > 0) {
					frame_dur = av_rescale_q(1, av_inv_q(fps), in_stream->time_base);
				}
			}
			if (frame_dur <= 0) {
				frame_dur = av_rescale_q(1, (AVRational){1, 24}, in_stream->time_base);
			}
			next_video_dts = pkt.dts + frame_dur;
		}
		if (pkt.pts == AV_NOPTS_VALUE) pkt.pts = pkt.dts;

		/* Use PTS for boundary checks (always valid after synthesis) */
		int64_t pkt_ts = pkt.pts != AV_NOPTS_VALUE ? pkt.pts : pkt.dts;
		const char *type = (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) ? "VIDEO" : "AUDIO";
		int is_key = (pkt.flags & AV_PKT_FLAG_KEY) != 0;

		if (pkt_ts != AV_NOPTS_VALUE) {
			int64_t pkt_time = av_rescale_q(pkt_ts, in_stream->time_base, AV_TIME_BASE_Q);

			if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO && (pkt.flags & AV_PKT_FLAG_KEY)) {
				lwsl_info("HLS-DEBUG: Seg %d parsed KEYFRAME pkt_time=%.3fs (pts=%lld). started=%d, finished=%d. start_time=%.3fs\n",
					  segment_idx, (double)pkt_time / AV_TIME_BASE, (long long)pkt.pts, started, video_finished, (double)start_time / AV_TIME_BASE);
			}

			if (!started) {
				if (has_video) {
					if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
						int64_t margin = av_rescale_q(500000, AV_TIME_BASE_Q, in_stream->time_base); /* 500ms margin */
						if ((pkt.flags & AV_PKT_FLAG_KEY) && (has_index ? (pkt.pts >= sinfo.start_pts - margin) : (pkt_time >= start_time - 500000))) {
							started = 1;
							actual_start_pts = pkt.dts;
							lwsl_info("HLS: Segment %d started writing video at pkt_time=%.3fs (pts=%lld, dts=%lld)\n",
								  segment_idx, (double)pkt_time / AV_TIME_BASE, (long long)pkt.pts, (long long)pkt.dts);

							/* Filter the audio buffer to discard packets before actual_start_pts */
							if (audio_idx >= 0 && actual_start_pts != AV_NOPTS_VALUE) {
								int64_t actual_start_pts_audio = av_rescale_q(actual_start_pts, in_ctx->streams[video_idx]->time_base, in_ctx->streams[audio_idx]->time_base);
								int write_idx = 0;
								for (int j = 0; j < audio_buffer_count; j++) {
									if (audio_buffer[j].pts < actual_start_pts_audio) {
										audio_packets_discarded++;
										lwsl_info("HLS-PKT-DEBUG: Seg %d Discard buffered AUDIO pts=%lld dts=%lld key=%d (before video start)\n",
											  segment_idx, (long long)audio_buffer[j].pts, (long long)audio_buffer[j].dts, (int)((audio_buffer[j].flags & AV_PKT_FLAG_KEY) != 0));
										av_packet_unref(&audio_buffer[j]);
									} else {
										if (write_idx != j) {
											audio_buffer[write_idx] = audio_buffer[j];
										}
										write_idx++;
									}
								}
								audio_buffer_count = write_idx;
							}
						} else {
							video_packets_discarded++;
							lwsl_info("HLS-PKT-DEBUG: Seg %d Discard %s pts=%lld dts=%lld key=%d: not started yet (video)\n",
								  segment_idx, type, (long long)pkt.pts, (long long)pkt.dts, is_key);
							av_packet_unref(&pkt);
							continue;
						}
					} else {
						/* Audio: buffer until video has started */
						if (!started) {
							int64_t start_time_audio = av_rescale_q(start_time, AV_TIME_BASE_Q, in_stream->time_base);
							int64_t margin = av_rescale_q(500000, AV_TIME_BASE_Q, in_stream->time_base);
							if (pkt.pts < start_time_audio - margin) {
								av_packet_unref(&pkt);
								continue;
							}
							if (audio_buffer_count < 512) {
								av_packet_move_ref(&audio_buffer[audio_buffer_count++], &pkt);
								lwsl_info("HLS-PKT-DEBUG: Seg %d Buffer AUDIO pts=%lld dts=%lld key=%d\n",
									  segment_idx, (long long)audio_buffer[audio_buffer_count - 1].pts,
									  (long long)audio_buffer[audio_buffer_count - 1].dts, is_key);
							} else {
								audio_packets_discarded++;
								lwsl_info("HLS-PKT-DEBUG: Seg %d Discard %s pts=%lld dts=%lld key=%d: not started yet (audio buffer overflow)\n",
									  segment_idx, type, (long long)pkt.pts, (long long)pkt.dts, is_key);
								av_packet_unref(&pkt);
							}
							continue;
						}
					}
				} else {
					if (has_index ? (pkt_time >= start_time) : (pkt_time >= start_time - 500000)) {
						started = 1;
						lwsl_info("HLS: Segment %d started writing audio-only at pkt_time=%.3fs (pts=%lld, dts=%lld)\n",
							  segment_idx, (double)pkt_time / AV_TIME_BASE, (long long)pkt.pts, (long long)pkt.dts);
					} else {
						audio_packets_discarded++;
						lwsl_info("HLS-PKT-DEBUG: Seg %d Discard %s pts=%lld dts=%lld key=%d: not started yet (audio-only)\n",
							  segment_idx, type, (long long)pkt.pts, (long long)pkt.dts, is_key);
						av_packet_unref(&pkt);
						continue;
					}
				}

			} else if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
				if (actual_start_pts != AV_NOPTS_VALUE && video_idx >= 0) {
					int64_t actual_start_pts_audio = av_rescale_q(actual_start_pts, in_ctx->streams[video_idx]->time_base, in_stream->time_base);
					if (pkt.pts < actual_start_pts_audio) {
						audio_packets_discarded++;
						lwsl_info("HLS-PKT-DEBUG: Seg %d Discard %s pts=%lld dts=%lld key=%d: PTS < actual_start_pts (%lld rescaled to %lld)\n",
							  segment_idx, type, (long long)pkt.pts, (long long)pkt.dts, is_key, (long long)actual_start_pts, (long long)actual_start_pts_audio);
						av_packet_unref(&pkt);
						continue;
					}
				}
			}



			/* Stop at end of segment on next video keyframe */
			if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
				if (pkt.flags & AV_PKT_FLAG_KEY) {
					int64_t margin = av_rescale_q(500000, AV_TIME_BASE_Q, in_stream->time_base); /* 500ms margin */
					/* If has_index and we know end_pts, stop EXACTLY at end_pts.
					 * Otherwise fallback to math. */
					if ((has_index && sinfo.end_pts != AV_NOPTS_VALUE && pkt.pts >= sinfo.end_pts - margin) || (!has_index && pkt_time >= end_time - 500000)) {
						lwsl_info("HLS: Segment %d reached next video keyframe at pkt_time=%.3fs (pts=%lld, dts=%lld). Video finished.\n",
							  segment_idx, (double)pkt_time / AV_TIME_BASE, (long long)pkt.pts, (long long)pkt.dts);
						video_finished = 1;
						end_time = av_rescale_q(pkt.pts, in_stream->time_base, AV_TIME_BASE_Q); /* Extend or shrink end_time to match ACTUAL video end (PTS) */
						av_packet_unref(&pkt);
						continue;
					}
				}
			}

			/* If there's no audio track, we must break once we're sure no more B-frames exist */
			if (video_finished && audio_idx < 0) {
				int64_t dts_time = av_rescale_q(pkt.dts != AV_NOPTS_VALUE ? pkt.dts : pkt.pts, in_stream->time_base, AV_TIME_BASE_Q);
				if (dts_time >= end_time) {
					lwsl_info("HLS-PKT-DEBUG: Seg %d Break %s pts=%lld dts=%lld key=%d: video_finished, audio_idx < 0, dts_time >= end_time\n",
						  segment_idx, type, (long long)pkt.pts, (long long)pkt.dts, is_key);
					av_packet_unref(&pkt);
					break;
				}
			}

			if (video_finished && in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
				video_packets_discarded++;
				lwsl_info("HLS-PKT-DEBUG: Seg %d Discard %s pts=%lld dts=%lld key=%d: video_finished\n",
					  segment_idx, type, (long long)pkt.pts, (long long)pkt.dts, is_key);
				av_packet_unref(&pkt);
				continue;
			}

			/* Stop audio after video has finished and audio reaches the actual video end boundary */
			if (video_finished && in_stream->codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
				if (pkt_time >= end_time) {
					lwsl_info("HLS-PKT-DEBUG: Seg %d Stop %s pts=%lld dts=%lld key=%d: audio pkt_time >= end_time\n",
						  segment_idx, type, (long long)pkt.pts, (long long)pkt.dts, is_key);
					av_packet_unref(&pkt);
					lwsl_info("HLS: Segment %d reached audio end at pkt_time=%.3fs. Stopping.\n",
						  segment_idx, (double)pkt_time / AV_TIME_BASE);
					break;
				}
			}
		}

		if (started && audio_buffer_count > 0 && pkt.stream_index == video_idx && audio_idx >= 0 && stream_mapping[audio_idx] >= 0) {
			int64_t target_dts_video = pkt.dts;
			int64_t target_dts_audio = av_rescale_q(target_dts_video, in_ctx->streams[video_idx]->time_base, in_ctx->streams[audio_idx]->time_base);
			int write_count = 0;
			for (int j = 0; j < audio_buffer_count; j++) {
				AVPacket *abuf_pkt = &audio_buffer[j];
				if (abuf_pkt->dts != AV_NOPTS_VALUE && abuf_pkt->dts <= target_dts_audio) {
					int out_stream_idx = stream_mapping[audio_idx];
					if (transcode_audio && audio_tx) {
						transcode_audio_packet(in_ctx, out_ctx, audio_tx, abuf_pkt,
									out_stream_idx, shift_offset_out_audio,
									&first_audio_pts, &first_audio_dts,
									&last_audio_pts, &last_audio_dts,
									&audio_packets_written, &last_dts[out_stream_idx],
									segment_idx);
					} else {
						abuf_pkt->stream_index = out_stream_idx;
						AVStream *out_stream = out_ctx->streams[out_stream_idx];

						if (first_audio_pts == AV_NOPTS_VALUE) {
							first_audio_pts = av_rescale_q_rnd(abuf_pkt->pts, in_ctx->streams[audio_idx]->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX) + shift_offset_out_audio;
							first_audio_dts = av_rescale_q_rnd(abuf_pkt->dts, in_ctx->streams[audio_idx]->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX) + shift_offset_out_audio;
						}

						abuf_pkt->pts = av_rescale_q_rnd(abuf_pkt->pts, in_ctx->streams[audio_idx]->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
						abuf_pkt->dts = av_rescale_q_rnd(abuf_pkt->dts, in_ctx->streams[audio_idx]->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
						if (abuf_pkt->pts != AV_NOPTS_VALUE) abuf_pkt->pts += shift_offset_out_audio;
						if (abuf_pkt->dts != AV_NOPTS_VALUE) abuf_pkt->dts += shift_offset_out_audio;
						abuf_pkt->duration = av_rescale_q(abuf_pkt->duration, in_ctx->streams[audio_idx]->time_base, out_stream->time_base);
						abuf_pkt->pos = -1;

						if (abuf_pkt->dts != AV_NOPTS_VALUE) {
							if (last_dts[out_stream_idx] != AV_NOPTS_VALUE && abuf_pkt->dts <= last_dts[out_stream_idx]) {
								abuf_pkt->dts = last_dts[out_stream_idx] + 1;
							}
							last_dts[out_stream_idx] = abuf_pkt->dts;
						}
						if (abuf_pkt->pts != AV_NOPTS_VALUE && abuf_pkt->pts < abuf_pkt->dts) {
							abuf_pkt->pts = abuf_pkt->dts;
						}

						last_audio_pts = abuf_pkt->pts;
						last_audio_dts = abuf_pkt->dts;
						audio_packets_written++;

						if (audio_packets_written <= 15 || video_finished) {
							lwsl_info("HLS-PKT-DEBUG: Seg %d Write AUDIO (buffered interleaved) pts=%lld dts=%lld\n",
								  segment_idx, (long long)abuf_pkt->pts, (long long)abuf_pkt->dts);
						}

						av_interleaved_write_frame(out_ctx, abuf_pkt);
					}
					av_packet_unref(abuf_pkt);
					write_count++;
				} else {
					break;
				}
			}
			if (write_count > 0) {
				if (write_count < audio_buffer_count) {
					memmove(&audio_buffer[0], &audio_buffer[write_count], (size_t)(audio_buffer_count - write_count) * sizeof(AVPacket));
				}
				audio_buffer_count -= write_count;
			}
		}

		int out_stream_idx = stream_mapping[pkt.stream_index];
		if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_AUDIO && transcode_audio && audio_tx) {
			transcode_audio_packet(in_ctx, out_ctx, audio_tx, &pkt,
						out_stream_idx, shift_offset_out_audio,
						&first_audio_pts, &first_audio_dts,
						&last_audio_pts, &last_audio_dts,
						&audio_packets_written, &last_dts[out_stream_idx],
						segment_idx);
			av_packet_unref(&pkt);
			continue;
		}

		pkt.stream_index = out_stream_idx;
		AVStream *out_stream = out_ctx->streams[out_stream_idx];

		pkt.pts = av_rescale_q_rnd(pkt.pts, in_stream->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
		pkt.dts = av_rescale_q_rnd(pkt.dts, in_stream->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
		int64_t stream_shift = (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) ? shift_offset_out_video : shift_offset_out_audio;
		if (pkt.pts != AV_NOPTS_VALUE) pkt.pts += stream_shift;
		if (pkt.dts != AV_NOPTS_VALUE) pkt.dts += stream_shift;
		pkt.duration = av_rescale_q(pkt.duration, in_stream->time_base, out_stream->time_base);
		pkt.pos = -1;

		if (pkt.dts != AV_NOPTS_VALUE) {
			if (last_dts[out_stream_idx] != AV_NOPTS_VALUE && pkt.dts <= last_dts[out_stream_idx]) {
				pkt.dts = last_dts[out_stream_idx] + 1;
			}
			last_dts[out_stream_idx] = pkt.dts;
		}
		if (in_stream->codecpar->codec_type != AVMEDIA_TYPE_VIDEO) {
			if (pkt.pts != AV_NOPTS_VALUE && pkt.pts < pkt.dts) {
				pkt.pts = pkt.dts;
			}
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

		int should_log = video_finished;
		if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO && video_packets_written <= 15) should_log = 1;
		if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_AUDIO && audio_packets_written <= 15) should_log = 1;
		if (should_log) {
			lwsl_info("HLS-PKT-DEBUG: Seg %d Write %s pts=%lld dts=%lld key=%d\n",
				  segment_idx, type, (long long)pkt.pts, (long long)pkt.dts, is_key);
		}

		av_interleaved_write_frame(out_ctx, &pkt);
		av_packet_unref(&pkt);
	}

	/* Flush any remaining buffered audio packets at the end */
	if (audio_idx >= 0 && stream_mapping[audio_idx] >= 0) {
		if (transcode_audio && audio_tx) {
			flush_audio_transcoder(out_ctx, audio_tx, stream_mapping[audio_idx],
					       &first_audio_pts, &first_audio_dts,
					       &last_audio_pts, &last_audio_dts,
					       &audio_packets_written, &last_dts[stream_mapping[audio_idx]],
					       segment_idx);
		} else {
			for (int j = 0; j < audio_buffer_count; j++) {
				AVPacket *abuf_pkt = &audio_buffer[j];
				int out_stream_idx = stream_mapping[audio_idx];
				abuf_pkt->stream_index = out_stream_idx;
				AVStream *out_stream = out_ctx->streams[out_stream_idx];

				if (first_audio_pts == AV_NOPTS_VALUE) {
					first_audio_pts = av_rescale_q_rnd(abuf_pkt->pts, in_ctx->streams[audio_idx]->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX) + shift_offset_out_audio;
					first_audio_dts = av_rescale_q_rnd(abuf_pkt->dts, in_ctx->streams[audio_idx]->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX) + shift_offset_out_audio;
				}

				abuf_pkt->pts = av_rescale_q_rnd(abuf_pkt->pts, in_ctx->streams[audio_idx]->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
				abuf_pkt->dts = av_rescale_q_rnd(abuf_pkt->dts, in_ctx->streams[audio_idx]->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
				if (abuf_pkt->pts != AV_NOPTS_VALUE) abuf_pkt->pts += shift_offset_out_audio;
				if (abuf_pkt->dts != AV_NOPTS_VALUE) abuf_pkt->dts += shift_offset_out_audio;
				abuf_pkt->duration = av_rescale_q(abuf_pkt->duration, in_ctx->streams[audio_idx]->time_base, out_stream->time_base);
				abuf_pkt->pos = -1;

				if (abuf_pkt->dts != AV_NOPTS_VALUE) {
					if (last_dts[out_stream_idx] != AV_NOPTS_VALUE && abuf_pkt->dts <= last_dts[out_stream_idx]) {
						abuf_pkt->dts = last_dts[out_stream_idx] + 1;
					}
					last_dts[out_stream_idx] = abuf_pkt->dts;
				}
				if (abuf_pkt->pts != AV_NOPTS_VALUE && abuf_pkt->pts < abuf_pkt->dts) {
					abuf_pkt->pts = abuf_pkt->dts;
				}

				last_audio_pts = abuf_pkt->pts;
				last_audio_dts = abuf_pkt->dts;
				audio_packets_written++;

				lwsl_info("HLS-PKT-DEBUG: Seg %d Write AUDIO (buffered final flush) pts=%lld dts=%lld\n",
					  segment_idx, (long long)abuf_pkt->pts, (long long)abuf_pkt->dts);

				av_interleaved_write_frame(out_ctx, abuf_pkt);
				av_packet_unref(abuf_pkt);
			}
		}
		audio_buffer_count = 0;
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
	if (audio_tx) {
		free_audio_transcoder(audio_tx);
	}
	for (int j = 0; j < audio_buffer_count; j++) {
		av_packet_unref(&audio_buffer[j]);
	}
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

	lwsl_notice("HLS: Segment %d summary:\n"
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
