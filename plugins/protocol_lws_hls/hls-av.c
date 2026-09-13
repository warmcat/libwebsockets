#include "private-lws-hls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>


/* thumbnail extraction: returns a malloc'd JPEG, or NULL */
static uint8_t *
run_thumb_task(struct per_vhost_data__lws_hls *vhd, struct hls_task *t,
	       int *jpeg_size_out)
{
        {
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

                *jpeg_size_out = jpeg_size;

                return jpeg_data;
        }
}

/* worker thread: file the thumbnail in the shared cache */
static void
finish_thumb_task(struct per_vhost_data__lws_hls *vhd, struct hls_task *t,
		  uint8_t *jpeg_data, int jpeg_size)
{
	struct thumb_cache *c = malloc(sizeof(*c));

	pthread_mutex_lock(&vhd->lock);

	if (c) {
		lws_strncpy(c->filename, t->filename, sizeof(c->filename));
		c->data = jpeg_data;
		c->len = (size_t)jpeg_size;

		lws_dll2_clear(&c->list);
		lws_dll2_add_head(&c->list, &vhd->thumb_cache);
		vhd->cache_count++;

		if (vhd->cache_count > 20) {
			/* drop the least-recently-used guy at the tail */
			struct thumb_cache *curr = lws_container_of(
					lws_dll2_get_tail(&vhd->thumb_cache),
					struct thumb_cache, list);

			lws_dll2_remove(&curr->list);
			if (curr->data)
				free(curr->data);
			free(curr);
			vhd->cache_count--;
		}
	} else
		free(jpeg_data);

	vhd->current_task_filename[0] = '\0';
	vhd->running = NULL;

	pthread_mutex_unlock(&vhd->lock);
	free(t);
}

/* worker thread: build one session's body into the task */
static void
run_body_task(struct per_vhost_data__lws_hls *vhd, struct hls_task *t)
{
	switch (t->type) {
	case HLS_TASK_INIT:
		lws_hls_build_init(vhd, vhd->media_dir, t->filename,
				   t->trackid, &t->cancel, &t->r);
		break;
	case HLS_TASK_MANIFEST:
		lws_hls_build_manifest(vhd, vhd->media_dir, t->filename,
				       t->trackid, &t->cancel, &t->r);
		break;
	case HLS_TASK_SEGMENT:
		lws_hls_build_segment(vhd, vhd->media_dir, t->filename,
				      t->trackid, t->segment_idx, &t->cancel,
				      &t->r);
		break;
	case HLS_TASK_STREAM:
		lws_hls_build_stream(vhd, vhd->media_dir, t->filename,
				     &t->cancel, &t->r);
		break;
	case HLS_TASK_SUB_PLAYLIST:
		lws_hls_build_sub_playlist(vhd, vhd->media_dir, t->filename,
					   t->trackid, &t->cancel, &t->r);
		break;
	case HLS_TASK_SUB_SEGMENT:
		lws_hls_build_sub_segment(vhd, vhd->media_dir, t->filename,
					  t->trackid, t->segment_idx,
					  &t->cancel, &t->r);
		break;
	default:
		t->r.status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		break;
	}
}

void
lws_hls_task_free(struct hls_task *t)
{
	if (!t)
		return;
	free(t->r.body);
	free(t);
}

void *
lws_hls_worker(void *d)
{
        struct per_vhost_data__lws_hls *vhd = (struct per_vhost_data__lws_hls *)d;

        while (1) {
		struct hls_task *t;

                pthread_mutex_lock(&vhd->lock);

                while (!vhd->thread_exit && !lws_dll2_get_head(&vhd->tasks)) {
                        pthread_cond_wait(&vhd->cond, &vhd->lock);
                }
                if (vhd->thread_exit) {
                        pthread_mutex_unlock(&vhd->lock);
                        break;
                }

                t = lws_container_of(lws_dll2_get_head(&vhd->tasks),
				     struct hls_task, list);
                lws_dll2_remove(&t->list);
		t->state = HLS_TASK_RUNNING;
		vhd->running = t;

		if (t->type == HLS_TASK_THUMB)
			lws_strncpy(vhd->current_task_filename, t->filename,
				    sizeof(vhd->current_task_filename));

                pthread_mutex_unlock(&vhd->lock);

		if (t->type == HLS_TASK_THUMB) {
			int jpeg_size = 0;
			uint8_t *jpeg = run_thumb_task(vhd, t, &jpeg_size);

			finish_thumb_task(vhd, t, jpeg, jpeg_size);
			lws_cancel_service(vhd->context);
			continue;
		}

		lwsl_notice("HLS-TRACE: worker running task type=%d '%s' seg=%d\n",
			    t->type, t->filename, t->segment_idx);

		run_body_task(vhd, t);

		lwsl_notice("HLS-TRACE: worker done task type=%d '%s' seg=%d -> status=%d len=%zu\n",
			    t->type, t->filename, t->segment_idx, t->r.status,
			    t->r.len);

		/*
		 * Hand it to the event loop.  Whether anyone is still waiting
		 * for it is the collector's business: t->pss is event loop
		 * state and we do not look at it.
		 */
		pthread_mutex_lock(&vhd->lock);
		t->state = HLS_TASK_DONE;
		vhd->running = NULL;
		lws_dll2_add_tail(&t->list, &vhd->done);
		pthread_mutex_unlock(&vhd->lock);

		lws_cancel_service(vhd->context);
        }

        return NULL;
}

int
lws_hls_queue_task(struct lws *wsi, struct per_vhost_data__lws_hls *vhd,
		   enum hls_task_type type, const char *filename,
		   const char *trackid, int segment_idx)
{
	struct per_session_data__lws_hls *pss =
		(struct per_session_data__lws_hls *)lws_wsi_user(wsi);
	struct hls_task *t;

	if (!vhd || !pss)
		return -1;

	/* one transaction, one task */
	if (pss->task) {
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR,
				       NULL);
		return -1;
	}

	t = calloc(1, sizeof(*t));
	if (!t) {
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR,
				       NULL);
		return -1;
	}

	t->type = type;
	t->state = HLS_TASK_PENDING;
	lws_strncpy(t->filename, filename, sizeof(t->filename));
	if (trackid)
		lws_strncpy(t->trackid, trackid, sizeof(t->trackid));
	t->segment_idx = segment_idx;
	t->pss = pss;
	t->r.status = HTTP_STATUS_INTERNAL_SERVER_ERROR;

	pss->task = t;
	pss->resp_ready = 0;

	pthread_mutex_lock(&vhd->lock);
	lws_dll2_add_tail(&t->list, &vhd->tasks);
	pthread_cond_signal(&vhd->cond);
	pthread_mutex_unlock(&vhd->lock);

	lwsl_notice("HLS-TRACE: queued task type=%d '%s' seg=%d\n",
		    type, filename, segment_idx);

	/*
	 * lws put the context's default content timeout on the transaction
	 * before calling us; we may legitimately wait longer than that for
	 * our turn on the worker
	 */
	lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
			HLS_TASK_TIMEOUT_SECS);

	return 0;
}

void
lws_hls_task_detach(struct per_vhost_data__lws_hls *vhd,
		    struct per_session_data__lws_hls *pss)
{
	struct hls_task *t = pss->task;

	if (!t)
		return;

	pss->task = NULL;

	pthread_mutex_lock(&vhd->lock);

	t->pss = NULL;
	t->cancel = 1;

	/*
	 * Pending: nobody else has a reference, drop it now.  Running: the
	 * worker will move it to done and the collector will find no pss
	 * and free it.  Done: the collector will do the same.
	 */
	if (t->state == HLS_TASK_PENDING) {
		lws_dll2_remove(&t->list);
		pthread_mutex_unlock(&vhd->lock);
		lws_hls_task_free(t);
		return;
	}

	pthread_mutex_unlock(&vhd->lock);
}

void
lws_hls_collect_done(struct per_vhost_data__lws_hls *vhd)
{
	lws_dll2_owner_t mine;

	/* take the whole done list under the lock, deal with it outside */
	memset(&mine, 0, sizeof(mine));
	pthread_mutex_lock(&vhd->lock);
	while (lws_dll2_get_head(&vhd->done)) {
		struct hls_task *t = lws_container_of(
				lws_dll2_get_head(&vhd->done),
				struct hls_task, list);

		lws_dll2_remove(&t->list);
		lws_dll2_add_tail(&t->list, &mine);
	}
	pthread_mutex_unlock(&vhd->lock);

	while (lws_dll2_get_head(&mine)) {
		struct hls_task *t = lws_container_of(lws_dll2_get_head(&mine),
						      struct hls_task, list);
		struct per_session_data__lws_hls *pss = t->pss;

		lws_dll2_remove(&t->list);

		if (pss) {
			pss->task = NULL;
			free(pss->segment_buf);
			pss->segment_buf = t->r.body;
			t->r.body = NULL;
			pss->segment_len = t->r.len;
			pss->segment_pos = 0;
			pss->resp_status = t->r.status;
			pss->resp_content_type = t->r.content_type;
			pss->resp_ready = 1;
			lwsl_notice("HLS-TRACE: collect type=%d '%s' seg=%d -> deliver status=%d len=%zu\n",
				    t->type, t->filename, t->segment_idx,
				    t->r.status, t->r.len);
			lws_callback_on_writable(pss->wsi);
		} else
			lwsl_notice("HLS-TRACE: collect type=%d '%s' seg=%d -> DROPPED (client gone)\n",
				    t->type, t->filename, t->segment_idx);

		lws_hls_task_free(t);
	}
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

        struct thumb_cache *c = NULL;
        lws_start_foreach_dll(struct lws_dll2 *, d,
                              lws_dll2_get_head(&vhd->thumb_cache)) {
                struct thumb_cache *cc = lws_container_of(d,
                                                struct thumb_cache, list);

                if (!strcmp(cc->filename, filename)) {
                        c = cc;
                        break;
                }
        } lws_end_foreach_dll(d);

        if (c) {
                pthread_mutex_unlock(&vhd->lock);
                lws_strncpy(pss->thumb_filename, filename,
                            sizeof(pss->thumb_filename));
                pss->waiting_for_thumbnail = 1;
                lws_callback_on_writable(wsi);
                return 0;
        }

        int already_queued = 0;
        lws_start_foreach_dll(struct lws_dll2 *, d2, lws_dll2_get_head(&vhd->tasks)) {
                struct hls_task *t = lws_container_of(d2,
                                                struct hls_task, list);

                if (t->type == HLS_TASK_THUMB &&
		    !strcmp(t->filename, filename)) {
                        already_queued = 1;
                        break;
                }
        } lws_end_foreach_dll(d2);

	/* ...or being extracted right now */
	if (vhd->current_task_filename[0] &&
	    !strcmp(vhd->current_task_filename, filename))
		already_queued = 1;

        if (!already_queued) {
                struct hls_task *nt = calloc(1, sizeof(*nt));
                if (!nt) {
                        pthread_mutex_unlock(&vhd->lock);
                        return -1;
                }
		nt->type = HLS_TASK_THUMB;
		nt->state = HLS_TASK_PENDING;
                lws_strncpy(nt->filename, filename, sizeof(nt->filename));

                lws_dll2_add_tail(&nt->list, &vhd->tasks);

                pthread_cond_signal(&vhd->cond);
        }
        
        pthread_mutex_unlock(&vhd->lock);
        
        lws_strncpy(pss->thumb_filename, filename,
                    sizeof(pss->thumb_filename));
        pss->waiting_for_thumbnail = 1;
        lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 30);
        
        return 0;
}


/* Custom AVIOContext writer for memory */
struct hls_buffer {
	uint8_t *ptr;
	size_t size;
	size_t allocated;
	int err;	/* sticky: allocation failed, or the cap was hit */
};

/*
 * Hard ceiling on how much muxed output we are willing to accumulate in RAM
 * for a single request.  One segment is only HLS_SEGMENT_DUR seconds, so
 * anything approaching this is either a pathological input or an attempt to
 * make us buffer without bound; fail the request instead of growing.
 */
#define HLS_BUF_MAX ((size_t)64 * 1024 * 1024)

/*
 * Bounds on how much input we will walk for one segment, independent of what
 * the keyframe index said.  The index decides where a segment ends, and when
 * it hands back an open-ended final segment (end_pts == AV_NOPTS_VALUE), or
 * its boundaries do not match what the demuxer actually produces, the demux
 * loop would otherwise carry on to EOF, transcoding the whole film's audio
 * into "one segment" and pinning the thread for minutes.
 *
 * HLS_BUF_MAX alone does not bound this: the mp4 muxer accumulates the
 * fragment in its own memory and only hands it to write_packet() at the
 * trailer, so the cap there trips after all the work has been done.
 *
 * A legitimate segment is HLS_SEGMENT_DUR plus at most one GOP, so these are
 * generous.  The byte count is of input packets handed to the muxer or the
 * audio transcoder, which for the transcode case overestimates the output.
 */
#define HLS_SEGMENT_MAX_SPAN_US ((int64_t)6 * HLS_SEGMENT_DUR * AV_TIME_BASE)
#define HLS_SEGMENT_MAX_PKTS 250000

#if LIBAVFORMAT_VERSION_MAJOR >= 61
static int write_packet(void *opaque, const uint8_t *buf, int buf_size) {
#else
static int write_packet(void *opaque, uint8_t *buf, int buf_size) {
#endif
	struct hls_buffer *hb = (struct hls_buffer *)opaque;
	size_t need;

	if (hb->err || buf_size < 0)
		return AVERROR(ENOMEM);

	need = hb->size + (size_t)buf_size;

	if (need > hb->allocated) {
		size_t na = need * 2;
		uint8_t *np;

		if (need > HLS_BUF_MAX) {
			hb->err = 1;
			return AVERROR(ENOMEM);
		}
		if (na > HLS_BUF_MAX)
			na = HLS_BUF_MAX;

		/*
		 * realloc() returning NULL must not clobber the old pointer:
		 * that both leaks it and leaves the memcpy() below writing at
		 * NULL + hb->size, ie, far past the guard page.
		 */
		np = realloc(hb->ptr, na);
		if (!np) {
			hb->err = 1;
			return AVERROR(ENOMEM);
		}

		hb->ptr = np;
		hb->allocated = na;
	}

	memcpy(hb->ptr + hb->size, buf, (size_t)buf_size);
	hb->size = need;

	return buf_size;
}

static size_t find_moof_offset(uint8_t *buf, size_t size) {
    size_t offset = 0;
    while (offset + 8 <= size) {
        uint32_t box_size = lws_ser_ru32be(&buf[offset]);
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

/*
 * Returns 0, or -1 if the muxer refused an encoded packet (the output buffer
 * cap tripped, or the avio is otherwise in error): there is no point decoding
 * and encoding anything further for this segment once that has happened.
 */
static int
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
                return 0;
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

                        ret = av_interleaved_write_frame(out_ctx, enc_pkt);
                        av_packet_unref(enc_pkt);
                        if (ret < 0) {
                                av_packet_free(&enc_pkt);
                                return -1;
                        }
                }
                av_packet_free(&enc_pkt);
        }

        return 0;
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

/*
 * Choose the input streams an output body is built from, per the rendition
 * selector (see enum hls_sel_kind).
 *
 * The muxed default takes the first video stream and, of the audio streams,
 * the first AAC one if any (no transcode needed), else the first.  "v" drops
 * the audio; "aN" takes audio stream N and, for the segment builder, keeps
 * the video stream as the timeline clock without writing it (*write_video
 * = 0), so audio-only segments cut at the same keyframes as the video ones.
 *
 * Returns -1 if sel is malformed or names a stream that is not audio.
 */
static int
hls_select_streams(AVFormatContext *in_ctx, const char *sel, int *video_idx,
		   int *audio_idx, int *write_video)
{
	enum hls_sel_kind kind;
	int want_audio;
	unsigned int i;

	*video_idx = -1;
	*audio_idx = -1;
	*write_video = 1;

	if (hls_parse_sel(sel, &kind, &want_audio))
		return -1;

	for (i = 0; i < in_ctx->nb_streams; i++) {
		const AVCodecParameters *cp = in_ctx->streams[i]->codecpar;

		if (cp->codec_type == AVMEDIA_TYPE_VIDEO) {
			if (*video_idx < 0)
				*video_idx = (int)i;
		} else if (cp->codec_type == AVMEDIA_TYPE_AUDIO) {
			if (*audio_idx < 0 || cp->codec_id == AV_CODEC_ID_AAC)
				*audio_idx = (int)i;
		}
	}

	switch (kind) {
	case HLS_SEL_MUXED:
		break;
	case HLS_SEL_VIDEO:
		*audio_idx = -1;
		break;
	case HLS_SEL_AUDIO:
		if (want_audio < 0 || (unsigned int)want_audio >= in_ctx->nb_streams ||
		    in_ctx->streams[want_audio]->codecpar->codec_type !=
							AVMEDIA_TYPE_AUDIO)
			return -1;
		*audio_idx = want_audio;
		*write_video = 0;
		break;
	}

	return 0;
}

void
lws_hls_build_init(struct per_vhost_data__lws_hls *vhd, const char *media_dir,
		   const char *filename, const char *sel, volatile int *cancel,
		   struct hls_result *r)
{
        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s/%s", media_dir, filename);

	(void)vhd;
	(void)cancel;
	r->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;

        AVFormatContext *in_ctx = NULL;
        if (avformat_open_input(&in_ctx, filepath, NULL, NULL) < 0) {
		r->status = HTTP_STATUS_NOT_FOUND;
                return;
        }
        in_ctx->flags |= AVFMT_FLAG_GENPTS;

        if (avformat_find_stream_info(in_ctx, NULL) < 0) {
                avformat_close_input(&in_ctx);
                return;
        }

        AVFormatContext *out_ctx = NULL;
        avformat_alloc_output_context2(&out_ctx, NULL, "mp4", NULL);
        if (!out_ctx) {
                avformat_close_input(&in_ctx);
                return;
        }

        int video_idx, audio_idx, write_video;

        if (hls_select_streams(in_ctx, sel, &video_idx, &audio_idx,
			       &write_video)) {
                avformat_free_context(out_ctx);
                avformat_close_input(&in_ctx);
                r->status = HTTP_STATUS_NOT_FOUND;
                return;
        }
        /* an audio-only init segment carries no video track at all */
        if (!write_video)
                video_idx = -1;

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
        memset(&hb, 0, sizeof(hb));
        hb.allocated = 1024 * 1024;
        hb.ptr = malloc(hb.allocated);
        if (!hb.ptr) {
                /* write_packet() would otherwise memcpy() into NULL */
                avformat_free_context(out_ctx);
                avformat_close_input(&in_ctx);
                return;
        }

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
                return;
        }
        av_write_trailer(out_ctx);
        av_dict_free(&opts);

        if (out_ctx) {
                av_free(out_ctx->pb->buffer);
                av_free(out_ctx->pb);
                avformat_free_context(out_ctx);
        }
        avformat_close_input(&in_ctx);

        /* hb.err: the muxed output hit the RAM cap or an allocation
         * failed, so the buffer contents are incomplete - do not ship it */
        if (hb.size == 0 || hb.err) {
                free(hb.ptr);
                return;
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

        r->body = malloc(LWS_PRE + send_size);
        if (!r->body) {
                free(hb.ptr);
                return;
        }

        memcpy(r->body + LWS_PRE, hb.ptr, send_size);
        r->len = send_size;
	r->content_type = "video/mp4";
	r->status = HTTP_STATUS_OK;
        free(hb.ptr);
}
#if LIBAVFORMAT_VERSION_MAJOR >= 58
#define get_index_count(st) avformat_index_get_entries_count(st)
#define get_index_entry(st, idx) avformat_index_get_entry(st, idx)
#else
#define get_index_count(st) ((st)->nb_index_entries)
#define get_index_entry(st, idx) (&((st)->index_entries[idx]))
#endif

/*
 * Is this video packet a keyframe?
 *
 * libavformat's matroska demuxer takes AV_PKT_FLAG_KEY from the container's
 * SimpleBlock flag / BlockGroup ReferenceBlock, and only for H.264 does it
 * recover a missing flag from the bitstream on demux.  A release MKV whose
 * muxer did not understand HEVC carries no keyframe flags for the video
 * track (typically just the first frame), and no video cues either, so
 * libavformat reports one keyframe in the whole film.  For us that means an
 * index with one entry, a playlist with one segment covering the entire
 * film, and a segment 0 that never sees the keyframe it is waiting for to
 * stop.
 *
 * So for HEVC and H.264, when the flag is missing, look at the NAL unit
 * types in the packet: an access unit whose first VCL NAL is an IRAP (HEVC
 * types 16..23) or an IDR slice (H.264 type 5) is a keyframe.  Packets in
 * MKV / MP4 are length-prefixed per the hvcC / avcC extradata; Annex B start
 * codes are handled for completeness.
 */
static int
hls_video_pkt_is_key(const AVStream *st, const AVPacket *pkt)
{
	const uint8_t *ed = st->codecpar->extradata;
	int edl = st->codecpar->extradata_size;
	const uint8_t *p = pkt->data, *end;
	int annexb = 0, lensz = 4, n = 0, hevc;

	if (pkt->flags & AV_PKT_FLAG_KEY)
		return 1;
	if (!p || pkt->size < 5)
		return 0;

	switch (st->codecpar->codec_id) {
	case AV_CODEC_ID_HEVC:
		hevc = 1;
		if (ed && edl >= 23 && ed[0] == 1)
			lensz = (ed[21] & 3) + 1;
		else
			annexb = 1;
		break;
	case AV_CODEC_ID_H264:
		hevc = 0;
		if (ed && edl >= 5 && ed[0] == 1)
			lensz = (ed[4] & 3) + 1;
		else
			annexb = 1;
		break;
	default:
		return 0;
	}

	end = p + pkt->size;

	/* parameter sets, AUD and SEI precede the first slice: walk a few */
	while (p + lensz < end && n++ < 64) {
		const uint8_t *nal;
		uint32_t nl = 0;
		int t;

		if (annexb) {
			while (p + 3 < end &&
			       !(p[0] == 0 && p[1] == 0 && p[2] == 1))
				p++;
			if (p + 3 >= end)
				return 0;
			nal = p + 3;
			p = nal;
			nl = (uint32_t)(end - nal);
		} else {
			int i;

			for (i = 0; i < lensz; i++)
				nl = (nl << 8) | *p++;
			nal = p;
			if (nl > (uint32_t)(end - p))
				return 0;
			p += nl;
		}
		if (nl < 2)
			continue;

		if (hevc) {
			t = (nal[0] >> 1) & 0x3f;
			if (t >= 16 && t <= 23)
				return 1;	/* BLA / IDR / CRA / reserved IRAP */
			if (t < 16)
				return 0;	/* a non-IRAP slice came first */
		} else {
			t = nal[0] & 0x1f;
			if (t == 5)
				return 1;	/* IDR slice */
			if (t >= 1 && t <= 4)
				return 0;	/* non-IDR slice / partition */
		}
	}

	return 0;
}

/* one video keyframe seen by scan_keyframes() */
struct scan_kf {
	int64_t pos;
	int64_t pts;
	int64_t dts;
	int size;
	int flagged;	/* the container marked it as a keyframe too */
};

/* well past anything legitimate: 55h at one keyframe a second */
#define HLS_SCAN_MAX_KF 200000

/*
 * For matroska, is there a Cluster header in the bytes just before the block
 * whose frame data starts at pos?  If so return its file position, else -1.
 *
 * What the matroska demuxer seeks to for an index entry must be a Cluster:
 * it parses from there at segment level, and a position inside a cluster
 * just gets skipped over element by element until the next Cluster ID, ie,
 * the seek lands one cluster late.  Cue entries carry Cluster positions, but
 * pkt->pos is the frame data position, so when we build the index from a
 * scan we have to find the enclosing Cluster ourselves.
 *
 * A Cluster starts [1F 43 B6 75][size vint][E7 Timecode ...][blocks...],
 * with optional A7 Position / AB PrevSize elements before the first block,
 * so for the first block of a cluster the ID is within a few dozen bytes
 * before the frame data.  The size vint and the following element ID are
 * checked too, so a chance 4-byte match inside the previous block's data is
 * not taken for a header.
 */
static int64_t
mkv_cluster_start_before(int fd, int64_t pos)
{
	uint8_t b[64];
	int64_t base = pos - (int64_t)sizeof(b);
	ssize_t n;
	int i;

	if (pos <= 0)
		return -1;
	if (base < 0)
		base = 0;

	n = pread(fd, b, (size_t)(pos - base), (off_t)base);
	if (n < 8)
		return -1;

	for (i = (int)n - 8; i >= 0; i--) {
		int j, vl;

		if (b[i] != 0x1f || b[i + 1] != 0x43 ||
		    b[i + 2] != 0xb6 || b[i + 3] != 0x75)
			continue;

		/* size vint: leading zero bits + 1 give its length */
		j = i + 4;
		if (!b[j])
			continue;
		vl = 1;
		while (!(b[j] & (0x80 >> (vl - 1))))
			vl++;
		j += vl;
		if (j >= (int)n)
			continue;
		/* Timecode, Position, PrevSize, CRC-32, Void, SilentTracks */
		if (b[j] == 0xe7 || b[j] == 0xa7 || b[j] == 0xab ||
		    b[j] == 0xbf || b[j] == 0xec || b[j] == 0x58)
			return base + i;
	}

	return -1;
}

/*
 * Walk the whole file from its first packet and collect every video
 * keyframe (as hls_video_pkt_is_key() sees them), for building the index of
 * a file with no cues, and for learning the true dts of the cue entries of
 * one that has them.
 *
 * This opens its own demuxer context on the file rather than reusing the
 * caller's.  On a file with no cues the matroska demuxer cannot seek at all,
 * and av_seek_frame() to 0 on the caller's context fails, but not before
 * libavformat has flushed the packets it buffered during stream probing: a
 * scan on that context starts wherever probing left the file position, which
 * for a small file is EOF, and for a large one is some seconds in.  A fresh
 * context always starts from the first packet.
 *
 * pkt->pos is what the demuxer will seek to for an index entry (for matroska
 * the containing cluster), so it is what the index entry gets.
 */
static int
scan_keyframes(const char *url, int video_idx, volatile int *cancel,
	       struct scan_kf **out, int *out_n)
{
	AVFormatContext *sc = NULL;
	struct scan_kf *arr = NULL;
	int n = 0, cap = 0, ret = -1, fd = -1;
	int64_t cluster_pos = -1;
	lws_usec_t t0 = lws_now_usecs();
	AVStream *st;
	AVPacket pkt;

	*out = NULL;
	*out_n = 0;

	/*
	 * This reads the whole file once, which for a large file without cues
	 * is seconds to minutes; say so up front and time it, since it happens
	 * on the worker thread and holds up other requests for the same vhost
	 * until it caches.
	 */
	lwsl_notice("HLS-INDEX: scanning '%s' for keyframes (whole-file read)...\n",
		    url ? url : "(null)");

	if (!url || avformat_open_input(&sc, url, NULL, NULL) < 0)
		return -1;
	if (avformat_find_stream_info(sc, NULL) < 0 ||
	    (unsigned int)video_idx >= sc->nb_streams)
		goto bail;
	st = sc->streams[video_idx];

	/* matroska: we need Cluster positions, see mkv_cluster_start_before() */
	if (sc->iformat && sc->iformat->name &&
	    !strncmp(sc->iformat->name, "matroska", 8))
		fd = open(url, O_RDONLY);

	while (av_read_frame(sc, &pkt) >= 0) {
		if (fd >= 0) {
			/* any stream's block may be the first in a cluster */
			int64_t c = mkv_cluster_start_before(fd, pkt.pos);

			if (c >= 0)
				cluster_pos = c;
		}

		if (pkt.stream_index == video_idx &&
		    hls_video_pkt_is_key(st, &pkt)) {
			if (n == cap) {
				int nc = cap ? cap * 2 : 256;
				struct scan_kf *na;

				if (nc > HLS_SCAN_MAX_KF)
					nc = HLS_SCAN_MAX_KF;
				if (nc == cap) {
					av_packet_unref(&pkt);
					break;
				}
				na = realloc(arr, (size_t)nc * sizeof(*na));
				if (!na) {
					av_packet_unref(&pkt);
					goto bail;
				}
				arr = na;
				cap = nc;
			}
			arr[n].pos = cluster_pos >= 0 ? cluster_pos : pkt.pos;
			arr[n].pts = pkt.pts;
			arr[n].dts = pkt.dts;
			arr[n].size = pkt.size;
			arr[n].flagged = !!(pkt.flags & AV_PKT_FLAG_KEY);
			n++;
		}
		av_packet_unref(&pkt);
		if (HLS_CANCELLED(cancel))
			goto bail;
	}

	*out = arr;
	*out_n = n;
	arr = NULL;
	ret = 0;

bail:
	if (fd >= 0)
		close(fd);
	free(arr);
	avformat_close_input(&sc);

	lwsl_notice("HLS-INDEX: scan of '%s' %s: %d keyframes in %llums\n",
		    url ? url : "(null)", ret ? "ABORTED" : "done", *out_n,
		    (unsigned long long)((lws_now_usecs() - t0) / 1000));

	return ret;
}

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

int
lws_hls_get_segment_info(struct per_vhost_data__lws_hls *vhd, const char *filename,
                         AVFormatContext *in_ctx, int video_idx, int target_seg_idx,
			 struct hls_segment_info *out_info, int *out_total_segments,
			 volatile int *cancel)
{
	AVStream *st = in_ctx->streams[video_idx];
	int count = get_index_count(st);

	/*
	 * Building the index means reading the whole file, and the result is
	 * shared, cached vhost state that unblocks every request for this
	 * file, not just the one that happened to trigger it.  So the scans
	 * below are governed by vhost teardown, never by the requesting
	 * client going away: if a client times out on the first (cold) request
	 * and disconnects, the scan must still finish and cache, so the
	 * client's retry - and everyone else - hits the cache instead of
	 * re-triggering the whole scan and never converging.  (The per-request
	 * `cancel` still governs the segment mux loop in lws_hls_build_segment,
	 * which is per-client and cheap.)
	 */
	volatile int *bc = vhd ? (volatile int *)&vhd->thread_exit : cancel;

	/* Check index cache first */
	struct hls_file_index *idx = NULL;
	if (vhd) {
		pthread_mutex_lock(&vhd->lock);
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&vhd->index_list)) {
			struct hls_file_index *curr = lws_container_of(d,
						struct hls_file_index, list);

			if (!strcmp(curr->filename, filename) &&
			    curr->video_idx == video_idx) {
				idx = curr;
				break;
			}
		} lws_end_foreach_dll(d);
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
		struct scan_kf *scanned = NULL;
		int n_scanned = 0;

		if (count <= 1) {
			/* no usable cues: scan the file once to build the index */
			lwsl_user("HLS-INDEX: %s: no usable cues (%d), scanning file to build index...\n",
				  filename, count);
			if (scan_keyframes(in_ctx->url, video_idx, bc,
					   &scanned, &n_scanned) < 0)
				return -1;
			for (int i = 0; i < n_scanned; i++)
				av_add_index_entry(st, scanned[i].pos, scanned[i].pts,
						   scanned[i].size, 0, AVINDEX_KEYFRAME);
			count = get_index_count(st);
			lwsl_notice("HLS-INDEX: %s: scan found %d keyframes\n",
				    filename, count);
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
					int hint = 0;

					/* the index came from cues: we still need to
					 * walk the file for the true dts of each entry */
					if (!scanned &&
					    scan_keyframes(in_ctx->url, video_idx, bc,
							   &scanned, &n_scanned) < 0) {
						free(new_idx->entries);
						free(new_idx);
						return -1;
					}

					for (int i = 0; i < count; i++) {
						const AVIndexEntry *entry = get_index_entry(st, i);
						new_idx->entries[i].pos = entry->pos;
						new_idx->entries[i].timestamp = entry->timestamp;
						new_idx->entries[i].min_distance = entry->min_distance;
						new_idx->entries[i].size = entry->size;
						new_idx->entries[i].flags = entry->flags;
						new_idx->entries[i].dts = AV_NOPTS_VALUE;

						/*
						 * Match on pts only: several
						 * keyframes can share a cluster,
						 * so pos does not identify one.
						 * Both lists are in file order, so
						 * resume from the last match.
						 */
						for (int j = 0; j < n_scanned; j++) {
							int k = (hint + j) % n_scanned;

							if (scanned[k].pts == entry->timestamp) {
								new_idx->entries[i].dts = scanned[k].dts;
								hint = k;
								break;
							}
						}
					}

					/*
					 * Keyframes the container did not flag
					 * mean the demuxer's own post-seek
					 * keyframe skipping will never let a
					 * packet through: segment seeks on this
					 * file must use AVSEEK_FLAG_ANY
					 */
					for (int k = 0; k < n_scanned; k++)
						if (!scanned[k].flagged) {
							new_idx->unflagged_keyframes = 1;
							break;
						}
					if (new_idx->unflagged_keyframes)
						lwsl_notice("HLS-INDEX: %s: keyframes not flagged by the container\n",
							    filename);

					pthread_mutex_lock(&vhd->lock);
					lws_dll2_clear(&new_idx->list);
					lws_dll2_add_head(&new_idx->list,
							  &vhd->index_list);
					idx = new_idx;
					pthread_mutex_unlock(&vhd->lock);
				} else {
					free(new_idx);
				}
			}
		} else if (count <= 1)
			lwsl_warn("HLS-INDEX: %s: only %d keyframe(s) found, the playlist will be a single segment\n",
				  filename, count);

		free(scanned);
	}

	lwsl_info("HLS-INDEX-DEBUG: video_idx=%d, count=%d, target_seg_idx=%d, duration=%lld\n",
		  video_idx, count, target_seg_idx, (long long)st->duration);
	if (count <= 0) {
		return -1;
	}

	if (out_info)
		out_info->seek_any = idx ? idx->unflagged_keyframes : 0;

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
	/* HLS-TRACE diagnostics for the degenerate-grouping case */
	int kf_flagged = 0;
	double max_dur_seen = 0.0;

	if (out_info && target_seg_idx == 0) {
		out_info->start_pts = current_start_pts;
		out_info->seek_pts = start_entry ? start_entry->timestamp : 0;
	}

	for (int i = 1; i < count; i++) {
		const AVIndexEntry *entry = get_index_entry(st, i);
		if (!entry) continue;
		if (!(entry->flags & AVINDEX_KEYFRAME)) continue;
		kf_flagged++;

		int64_t entry_dts = AV_NOPTS_VALUE;
		if (idx && i < idx->count && idx->entries[i].dts != AV_NOPTS_VALUE) {
			entry_dts = idx->entries[i].dts;
		} else {
			entry_dts = get_entry_dts(st, entry);
		}

		double dur = (double)(entry_dts - current_start_pts) * av_q2d(st->time_base);
		if (dur > max_dur_seen)
			max_dur_seen = dur;
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

	/*
	 * Sanity: the keyframe grouping above should give roughly
	 * duration / HLS_SEGMENT_DUR segments.  Some real files defeat it - the
	 * whole film collapses into one "final" segment (seen on a 2h20 x265
	 * rip: 1418 keyframes scanned, yet current_seg stays 0), which makes
	 * the playlist a single giant segment and every segment open-ended.
	 * If the grouping produced far fewer segments than the file's declared
	 * duration implies, treat the index as usable for seeking but not for
	 * segmentation: fail here so the caller falls back to uniform
	 * duration-based segments.  Those still seek accurately, because the
	 * keyframe index we populated on the context above stays in place.
	 */
	{
		double total_dur_s = 0.0;

		if (st->duration > 0)
			total_dur_s = (double)st->duration * av_q2d(st->time_base);
		else if (in_ctx->duration > 0)
			total_dur_s = (double)in_ctx->duration / AV_TIME_BASE;

		/* only the diagnostic calls (manifest's -1 probe, and seg 0),
		 * so a long file's per-segment manifest loop does not flood */
		if (target_seg_idx <= 0) {
			lwsl_notice("HLS-TRACE: get_seg_info '%s' target=%d: index count=%d grouped=%d seg(s) "
				    "dur=%.0fs tb=%d/%d start_pts=%lld end_pts=%lld seek_any=%d\n",
				    filename, target_seg_idx, count, current_seg + 1,
				    total_dur_s, st->time_base.num, st->time_base.den,
				    out_info ? (long long)out_info->start_pts : -1,
				    out_info ? (long long)out_info->end_pts : -1,
				    out_info ? out_info->seek_any : -1);
			if (count > 0) {
				const AVIndexEntry *e0 = get_index_entry(st, 0);
				const AVIndexEntry *e1 = count > 1 ? get_index_entry(st, 1) : NULL;
				const AVIndexEntry *e2 = count > 2 ? get_index_entry(st, 2) : NULL;
				lwsl_notice("HLS-TRACE:   entry ts[0]=%lld idxdts[0]=%lld ts[1]=%lld ts[2]=%lld\n",
					    e0 ? (long long)e0->timestamp : -1,
					    (idx && idx->count > 0) ? (long long)idx->entries[0].dts : -1,
					    e1 ? (long long)e1->timestamp : -1,
					    e2 ? (long long)e2->timestamp : -1);
			}
		}

		if (total_dur_s > 2.0 * HLS_SEGMENT_DUR &&
		    total_dur_s / (double)(current_seg + 1) > 2.0 * HLS_SEGMENT_DUR) {
			const AVIndexEntry *el = count > 0 ? get_index_entry(st, count - 1) : NULL;

			lwsl_warn("HLS-INDEX: %s: keyframe grouping degenerate "
				  "(%d segment(s) for %.0fs); using duration-based "
				  "segments\n", filename, current_seg + 1,
				  total_dur_s);
			/* one line with everything needed to see WHY it degenerated */
			lwsl_warn("HLS-INDEX:   diag: count=%d kf_flagged=%d tb=%d/%d "
				  "start_dts=%lld idxdts0=%lld ts[first]=%lld ts[last]=%lld "
				  "idxdts[last]=%lld max_dur=%.3fs\n",
				  count, kf_flagged, st->time_base.num, st->time_base.den,
				  (long long)current_start_pts,
				  (idx && idx->count > 0) ? (long long)idx->entries[0].dts : -1,
				  start_entry ? (long long)start_entry->timestamp : -1,
				  el ? (long long)el->timestamp : -1,
				  (idx && idx->count > 0) ? (long long)idx->entries[idx->count - 1].dts : -1,
				  max_dur_seen);
			return -1;
		}
	}

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

void
lws_hls_build_manifest(struct per_vhost_data__lws_hls *vhd,
		       const char *media_dir, const char *filename,
		       const char *sel, volatile int *cancel, struct hls_result *r)
{
	char filepath[1024];
	enum hls_sel_kind kind;
	int sel_audio;
	/*
	 * The muxed playlist lives at /avstream/<file> and references
	 * ../init/<file>; a rendition playlist lives one level deeper at
	 * /avstream/<file>/<sel> and references ../../init/<file>/<sel>
	 */
	const char *up;
	char selsuffix[24];

	snprintf(filepath, sizeof(filepath), "%s/%s", media_dir, filename);

	r->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;

	if (hls_parse_sel(sel, &kind, &sel_audio)) {
		r->status = HTTP_STATUS_NOT_FOUND;
		return;
	}
	if (kind == HLS_SEL_MUXED) {
		up = "../";
		selsuffix[0] = '\0';
	} else {
		up = "../../";
		lws_snprintf(selsuffix, sizeof(selsuffix), "/%s", sel);
	}

	AVFormatContext *fmt_ctx = NULL;
	if (avformat_open_input(&fmt_ctx, filepath, NULL, NULL) < 0) {
		r->status = HTTP_STATUS_NOT_FOUND;
		return;
	}
	fmt_ctx->flags |= AVFMT_FLAG_GENPTS;

	if (avformat_find_stream_info(fmt_ctx, NULL) < 0) {
		avformat_close_input(&fmt_ctx);
		return;
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
		return;
	}

	int has_index = 0;
	if (video_idx >= 0 && lws_hls_get_segment_info(vhd, filename, fmt_ctx, video_idx, -1, NULL, &total_segments, cancel) == 0) {
		has_index = 1;
	} else if (HLS_CANCELLED(cancel)) {
		avformat_close_input(&fmt_ctx);
		return;
	} else {
		int64_t segdur = (int64_t)HLS_SEGMENT_DUR * AV_TIME_BASE;
		int64_t n = duration / segdur;

		if (duration % segdur)
			n++;
		if (n > HLS_MAX_SEGMENTS)
			n = HLS_MAX_SEGMENTS;
		total_segments = (int)n;
	}

	/*
	 * total_segments came from the container (its keyframe index, or its
	 * declared duration); clamp it before it is used for the sizing
	 * arithmetic and the composition loop below, so a hostile file cannot
	 * overflow the size computation or make the loop unbounded.
	 */
	if (total_segments < 0)
		total_segments = 0;
	if (total_segments > HLS_MAX_SEGMENTS) {
		lwsl_warn("%s: %s: %d segments, clamping to %d\n", __func__,
			  filename, total_segments, HLS_MAX_SEGMENTS);
		total_segments = HLS_MAX_SEGMENTS;
	}

	/* We must compute max target duration from index to be standard compliant */
	int target_duration = HLS_SEGMENT_DUR;
	if (has_index) {
		double max_dur = 0;
		for (int i = 0; i < total_segments; i++) {
			struct hls_segment_info sinfo;
			memset(&sinfo, 0, sizeof(sinfo));
			sinfo.end_pts = AV_NOPTS_VALUE;
			if (lws_hls_get_segment_info(vhd, filename, fmt_ctx, video_idx, i, &sinfo, NULL, cancel) == 0) {
				if (sinfo.duration_sec > max_dur) max_dur = sinfo.duration_sec;
			}
		}
		/* clamp before the cast: (int) of an out-of-range double is UB */
		if (max_dur > HLS_MAX_SEG_DUR)
			max_dur = HLS_MAX_SEG_DUR;
		if (max_dur < 0.0)
			max_dur = 0.0;
		target_duration = (int)(max_dur + 0.999); /* round up */
	}

	/*
	 * Size from the real string lengths rather than a fixed 128 bytes per
	 * line: the filename (up to 255 bytes) appears in every EXTINF entry.
	 * Composition itself uses the clamped hls_append_fmt() cursor, so even
	 * if this estimate were wrong the playlist can only truncate (F-059).
	 */
	size_t fnlen = strlen(filename) + sizeof(selsuffix);
	size_t m3u8_max = 256 + fnlen + (size_t)total_segments * (64 + fnlen);
	char *m3u8 = malloc(LWS_PRE + m3u8_max);
	if (!m3u8) {
		avformat_close_input(&fmt_ctx);
		return;
	}

	char *body = m3u8 + LWS_PRE;
	char *p_m3u8 = body;

	*body = '\0';
	p_m3u8 = hls_append_fmt(p_m3u8, body, m3u8_max,
		"#EXTM3U\n"
		"#EXT-X-VERSION:7\n"
		"#EXT-X-TARGETDURATION:%d\n"
		"#EXT-X-MEDIA-SEQUENCE:0\n"
		"#EXT-X-MAP:URI=\"%sinit/%s%s\"\n"
		"#EXT-X-PLAYLIST-TYPE:VOD\n", target_duration, up, filename,
		selsuffix);

	for (int i = 0; i < total_segments; i++) {
		double dur = (double)HLS_SEGMENT_DUR;
		if (has_index) {
			struct hls_segment_info sinfo;
			memset(&sinfo, 0, sizeof(sinfo));
			sinfo.end_pts = AV_NOPTS_VALUE;
			if (lws_hls_get_segment_info(vhd, filename, fmt_ctx, video_idx, i, &sinfo, NULL, cancel) == 0) {
				dur = sinfo.duration_sec;
			}
		} else {
			if (i == total_segments - 1) {
				int64_t rem = duration - (int64_t)i * HLS_SEGMENT_DUR * AV_TIME_BASE;
				dur = (double)rem / AV_TIME_BASE;
			}
		}
		/* keep "%f" of a container-derived double to a sane width */
		if (!(dur > 0.0))
			dur = 0.1;
		if (dur > HLS_MAX_SEG_DUR)
			dur = HLS_MAX_SEG_DUR;
		p_m3u8 = hls_append_fmt(p_m3u8, body, m3u8_max,
			"#EXTINF:%f,\n"
			"%ssegment/%s%s/%d\n",
			dur, up, filename, selsuffix, i);
	}

	avformat_close_input(&fmt_ctx);

	p_m3u8 = hls_append_fmt(p_m3u8, body, m3u8_max, "#EXT-X-ENDLIST\n");

	/* m3u8 already carries the LWS_PRE headroom, hand it over as is */
	r->body = (uint8_t *)m3u8;
	r->len = (size_t)(p_m3u8 - body);
	r->content_type = "application/vnd.apple.mpegurl";
	r->status = HTTP_STATUS_OK;
}


void
lws_hls_build_segment(struct per_vhost_data__lws_hls *vhd,
		      const char *media_dir, const char *filename,
		      const char *sel, int segment_idx, volatile int *cancel,
		      struct hls_result *r)
{
	char filepath[1024];
	snprintf(filepath, sizeof(filepath), "%s/%s", media_dir, filename);

	r->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;

	AVFormatContext *in_ctx = NULL;
	if (avformat_open_input(&in_ctx, filepath, NULL, NULL) < 0) {
		r->status = HTTP_STATUS_NOT_FOUND;
		return;
	}
	in_ctx->flags |= AVFMT_FLAG_GENPTS;

	if (avformat_find_stream_info(in_ctx, NULL) < 0) {
		avformat_close_input(&in_ctx);
		return;
	}

	AVFormatContext *out_ctx = NULL;
	avformat_alloc_output_context2(&out_ctx, NULL, "mp4", NULL);
	if (!out_ctx) {
		avformat_close_input(&in_ctx);
		return;
	}

	struct hls_audio_transcoder *audio_tx = NULL;
	int transcode_audio = 0;

	int *stream_mapping = malloc((size_t)in_ctx->nb_streams * sizeof(int));
	if (!stream_mapping) {
		avformat_free_context(out_ctx);
		avformat_close_input(&in_ctx);
		return;
	}
	for (unsigned int i = 0; i < in_ctx->nb_streams; i++) {
		stream_mapping[i] = -1;
	}
	int stream_index = 0;
	int has_video = 0;
	int video_idx, audio_idx, write_video;

	if (hls_select_streams(in_ctx, sel, &video_idx, &audio_idx,
			       &write_video)) {
		free(stream_mapping);
		avformat_free_context(out_ctx);
		avformat_close_input(&in_ctx);
		r->status = HTTP_STATUS_NOT_FOUND;
		return;
	}

	/*
	 * Audio-only rendition: the video stream still drives the segment
	 * boundaries below (has_video, the keyframe wait, the audio buffer
	 * drain keyed on video packets), it just never gets an output stream
	 * or written.
	 */
	if (video_idx >= 0)
		has_video = 1;
	if (video_idx >= 0 && write_video) {
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
	memset(&hb, 0, sizeof(hb));
	hb.allocated = 1024 * 1024; /* 1MB init */
	hb.ptr = malloc(hb.allocated);
	if (!hb.ptr) {
		/* write_packet() would otherwise memcpy() into NULL */
		if (audio_tx)
			free_audio_transcoder(audio_tx);
		avformat_free_context(out_ctx);
		avformat_close_input(&in_ctx);
		free(stream_mapping);
		return;
	}

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

	/*
	 * these are declared and initialized before any goto done below, so
	 * that the error paths at done: never see them indeterminate
	 */
	int64_t last_dts[32];
	for (int i = 0; i < 32; i++) {
		last_dts[i] = AV_NOPTS_VALUE;
	}
	int started = 0;
	int64_t actual_start_pts = AV_NOPTS_VALUE;
	int video_finished = 0;
	int video_kf_seen = 0;	/* HLS-TRACE: video keyframes the loop saw */
	/*
	 * segment window; also read from the done: path (summary + HLS-TRACE),
	 * so initialised here before any goto done rather than below
	 */
	int64_t start_time = (int64_t)segment_idx * HLS_SEGMENT_DUR * AV_TIME_BASE;
	int64_t end_time = (int64_t)(segment_idx + 1) * HLS_SEGMENT_DUR * AV_TIME_BASE;
	int has_index = 0;
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

	struct hls_segment_info sinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.end_pts = AV_NOPTS_VALUE;

	if (video_idx >= 0 && lws_hls_get_segment_info(vhd, filename, in_ctx, video_idx, segment_idx, &sinfo, NULL, cancel) == 0) {
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
	
	if (HLS_CANCELLED(cancel))
		goto done;

	if (!has_index && duration > 0 && start_time >= duration) {
		r->status = HTTP_STATUS_NOT_FOUND;
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
		/*
		 * On a file whose container does not flag its keyframes, the
		 * matroska demuxer would otherwise discard every packet after
		 * the seek waiting for a flagged one that never comes.  With
		 * AVSEEK_FLAG_ANY it delivers from the requested timestamp
		 * (logging "keyframes not correctly marked" once), and the
		 * loop below already discards anything before the keyframe it
		 * is waiting for.
		 */
		int seek_flags = sinfo.seek_any ? AVSEEK_FLAG_ANY :
						  AVSEEK_FLAG_FRAME;

		/* the seek itself is functional, only the ret capture is for logs */
#if (_LWS_ENABLED_LOGS & LLL_INFO)
		int ret = avformat_seek_file(in_ctx, video_idx, target_ts - 500, target_ts, max_ts, seek_flags);

		lwsl_info("HLS-DEBUG: Segment %d video seek requested to %lld (flags %d) -> ret=%d\n",
			  segment_idx, (long long)target_ts, seek_flags, ret);
#else
		avformat_seek_file(in_ctx, video_idx, target_ts - 500, target_ts, max_ts, seek_flags);
#endif
	} else {
		/*
		 * Duration-based segment (no per-segment index boundaries).
		 * get_segment_info() still populated the context's keyframe
		 * index and reported seek_any, so seek by time against that
		 * index, and on a file with unflagged keyframes seek with
		 * AVSEEK_FLAG_ANY for the same reason as the indexed path.
		 */
		int gflags = sinfo.seek_any ? AVSEEK_FLAG_ANY : 0;
#if (_LWS_ENABLED_LOGS & LLL_INFO)
		int ret = avformat_seek_file(in_ctx, -1, INT64_MIN, start_time, start_time, gflags);

		lwsl_info("HLS: Segment %d generic seek requested to %.3fs (flags %d) -> ret=%d\n",
			  segment_idx, (double)start_time / AV_TIME_BASE, gflags, ret);
#else
		avformat_seek_file(in_ctx, -1, INT64_MIN, start_time, start_time, gflags);
#endif
	}

	int64_t next_video_dts = AV_NOPTS_VALUE;
	if (has_index) {
		next_video_dts = sinfo.start_pts;
	}

	/* see HLS_SEGMENT_MAX_SPAN_US: bounds on the walk that do not depend
	 * on the index or the demuxer's timestamps being what we expected */
	int64_t pkts_read = 0;
	size_t bytes_fed = 0;

	AVPacket pkt;
	while (av_read_frame(in_ctx, &pkt) >= 0) {
		AVStream *in_stream  = in_ctx->streams[pkt.stream_index];

		if (HLS_CANCELLED(cancel)) {
			/* the session went away: nobody wants this */
			hb.err = 1;
			av_packet_unref(&pkt);
			break;
		}
		if (hb.err) {
			lwsl_warn("HLS: Segment %d: output cap hit, stopping\n",
				  segment_idx);
			av_packet_unref(&pkt);
			break;
		}
		if (++pkts_read > HLS_SEGMENT_MAX_PKTS ||
		    bytes_fed > HLS_BUF_MAX) {
			lwsl_warn("HLS: Segment %d: %lld pkts / %zu bytes without "
				  "reaching segment end, stopping\n", segment_idx,
				  (long long)pkts_read, bytes_fed);
			av_packet_unref(&pkt);
			break;
		}

		/* the unwritten video clock of an audio-only rendition
		 * still goes through the boundary logic below */
		if (stream_mapping[pkt.stream_index] < 0 &&
		    !(has_video && pkt.stream_index == video_idx)) {
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
		/*
		 * Keyframe as far as we are concerned, whether or not the
		 * container said so (see hls_video_pkt_is_key()).  Mark the
		 * packet too, so the mp4 muxer's sync sample table agrees.
		 */
		int is_key = 0;
		if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO &&
		    hls_video_pkt_is_key(in_stream, &pkt)) {
			is_key = 1;
			pkt.flags |= AV_PKT_FLAG_KEY;
		}
		/* only referenced from info logs, which may be built out */
#if (_LWS_ENABLED_LOGS & LLL_INFO)
		const char *type = (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) ? "VIDEO" : "AUDIO";
#else
		(void)is_key;
#endif

		/* HLS-TRACE: every video keyframe the loop sees, and how the
		 * end test would judge it, so a stuck segment is legible */
		if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO && is_key) {
			video_kf_seen++;
			lwsl_notice("HLS-TRACE: seg %d kf#%d pts=%lld dts=%lld started=%d vfin=%d end_pts=%lld\n",
				    segment_idx, video_kf_seen, (long long)pkt.pts,
				    (long long)pkt.dts, started, video_finished,
				    (long long)sinfo.end_pts);
		}

		if (pkt_ts != AV_NOPTS_VALUE) {
			int64_t pkt_time = av_rescale_q(pkt_ts, in_stream->time_base, AV_TIME_BASE_Q);

			/*
			 * Whether or not we have started, and whatever the index
			 * claimed the segment end was, do not walk further past
			 * the segment start than a legitimate segment could span
			 */
			if (pkt_time - start_time > HLS_SEGMENT_MAX_SPAN_US) {
				lwsl_warn("HLS: Segment %d: input %.1fs past segment "
					  "start without reaching its end "
					  "(started=%d, video_finished=%d), "
					  "stopping\n", segment_idx,
					  (double)(pkt_time - start_time) / AV_TIME_BASE,
					  started, video_finished);
				av_packet_unref(&pkt);
				break;
			}

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
					/* If has_index and we know end_pts, stop EXACTLY at end_pts.
					 * Otherwise fallback to math. */
					if ((has_index && sinfo.end_pts != AV_NOPTS_VALUE && pkt.pts >= sinfo.end_pts) || (!has_index && pkt_time >= end_time - 500000)) {
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
					bytes_fed += (size_t)abuf_pkt->size;
					if (transcode_audio && audio_tx) {
						if (transcode_audio_packet(in_ctx, out_ctx, audio_tx, abuf_pkt,
									out_stream_idx, shift_offset_out_audio,
									&first_audio_pts, &first_audio_dts,
									&last_audio_pts, &last_audio_dts,
									&audio_packets_written, &last_dts[out_stream_idx],
									segment_idx) < 0)
							hb.err = 1;
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
		if (out_stream_idx < 0) {
			/* video clock packet of an audio-only rendition: it
			 * has done its job driving the boundaries above */
			av_packet_unref(&pkt);
			continue;
		}
		bytes_fed += (size_t)pkt.size;
		if (in_stream->codecpar->codec_type == AVMEDIA_TYPE_AUDIO && transcode_audio && audio_tx) {
			if (transcode_audio_packet(in_ctx, out_ctx, audio_tx, &pkt,
						out_stream_idx, shift_offset_out_audio,
						&first_audio_pts, &first_audio_dts,
						&last_audio_pts, &last_audio_dts,
						&audio_packets_written, &last_dts[out_stream_idx],
						segment_idx) < 0)
				hb.err = 1;
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

	/* Flush any remaining buffered audio packets at the end (not worth
	 * draining the transcoder into an output we are going to discard) */
	if (audio_idx >= 0 && stream_mapping[audio_idx] >= 0) {
		if (transcode_audio && audio_tx) {
			if (!hb.err)
				flush_audio_transcoder(out_ctx, audio_tx,
					stream_mapping[audio_idx],
					&first_audio_pts, &first_audio_dts,
					&last_audio_pts, &last_audio_dts,
					&audio_packets_written,
					&last_dts[stream_mapping[audio_idx]],
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

	if (video_idx >= 0 && stream_mapping[video_idx] >= 0) {
		video_out_time_base = out_ctx->streams[stream_mapping[video_idx]]->time_base;
	}
	if (audio_idx >= 0 && stream_mapping[audio_idx] >= 0) {
		audio_out_time_base = out_ctx->streams[stream_mapping[audio_idx]]->time_base;
	}

done:
	/* freed here, not on the success path, so the goto done above (eg,
	 * avformat_write_header() refusing a codec the mp4 muxer won't take,
	 * which a client can trigger repeatably) does not leak it */
	av_dict_free(&opts);

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

	/* hb.err: the muxed output hit the RAM cap or an allocation failed,
	 * so the buffer contents are incomplete - do not ship it */
	if (hb.size == 0 || hb.err) {
		free(hb.ptr);
		return;
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

	lwsl_notice("HLS-TRACE: seg %d end: has_index=%d start_time=%.3fs end_time=%.3fs "
		    "video_kf_seen=%d started=%d video_finished=%d hb.err=%d\n",
		    segment_idx, has_index, (double)start_time / AV_TIME_BASE,
		    end_time == INT64_MAX ? -1.0 : (double)end_time / AV_TIME_BASE,
		    video_kf_seen, started, video_finished, hb.err);

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

        r->body = malloc(LWS_PRE + send_size);
        if (!r->body) {
                free(hb.ptr);
                return;
        }

        memcpy(r->body + LWS_PRE, hb.ptr + offset, send_size);
        r->len = send_size;
	r->content_type = "video/mp4";
	r->status = HTTP_STATUS_OK;
	free(hb.ptr);
}
