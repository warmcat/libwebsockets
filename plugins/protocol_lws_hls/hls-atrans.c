/*
 * libwebsockets - small server side websockets and websockets implementation
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
 * Pre-transcoded audio "shadow" cache.
 *
 * Audio the browser cannot play (AC3, EAC3, ...) used to be transcoded to AAC
 * per requested segment: that restarts the encoder at every segment boundary,
 * and the restart (with AAC priming) duplicated a short sliver of audio into
 * both sides of each boundary, which accumulated into audible drift.  Here
 * the whole audio stream is transcoded once, ahead of time, into a shadow
 * file under <media-dir>/.atrans/<sha1 of "filename|stream">.m4a, and the
 * segment builder cuts audio from it exactly as it does for passthrough
 * audio.  The shadow's AAC timeline is the source audio's, so segments stay
 * frame-adjacent with no encoder restarts at all.
 *
 * The shadow is managed like the keyframe index is (see hls-index.c): hashed
 * name, a header recording which media file at what size and mtime it was
 * built from, removed when the media goes or changes (delete through us,
 * init sweep, hourly sweep), and an hourly size cap with oldest-first
 * eviction.  Builds run on their own thread so a long transcode does not
 * hold up the worker or the indexer; segment tasks park until the shadow
 * covers the part of the timeline they need, so playback can start as soon
 * as the head of the file has been transcoded rather than after the whole
 * file.  A build that failed recently is not parked behind again: those
 * segments fall back to the inline per-segment transcode.
 */

#include "private-lws-hls.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define HLS_ATRANS_SUBDIR	".atrans"
#define HLS_ATRANS_MAGIC	"LWSHLSAT"
#define HLS_ATRANS_VERSION	1
/* how long a failed build keeps the worker from parking behind another */
#define HLS_ATRANS_RETRY_US	(600 * LWS_US_PER_SEC)
/*
 * How far the published coverage trails the transcode cursor: the muxer
 * flushes a fragment at a time and buffers internally, and readers must
 * never be told data is there when it is not.  The short-read retry in the
 * segment builder covers the rest of the race.
 */
#define HLS_ATRANS_COVER_LAG_US	(2 * LWS_US_PER_SEC)
/* fMP4 fragment duration in the shadow: the coverage granularity */
#define HLS_ATRANS_FRAG_US	(1 * LWS_US_PER_SEC)
/* total size of completed shadows we keep before evicting oldest-first */
#define HLS_ATRANS_MAX_BYTES	((int64_t)4 * 1024 * 1024 * 1024)

struct hls_atrans_hdr {
	char		magic[8];
	uint32_t	version;
	uint32_t	audio_idx;
	int64_t		size;	/* of the media file when it was transcoded */
	int64_t		mtime;
	char		filename[256];
};

static void
hls_atrans_dir(const char *media_dir, char *buf, size_t len)
{
	lws_snprintf(buf, len, "%s/" HLS_ATRANS_SUBDIR, media_dir);
}

static void
hls_atrans_paths(const char *media_dir, const char *filename, int audio_idx,
		 char *m4a, size_t m4a_len, char *hdr, size_t hdr_len)
{
	unsigned char digest[20];
	char key[300], hex[41];

	lws_snprintf(key, sizeof(key), "%s|%d", filename, audio_idx);
	lws_SHA1((const unsigned char *)key, strlen(key), digest);
	lws_hex_from_byte_array(digest, sizeof(digest), hex, sizeof(hex));

	if (m4a)
		lws_snprintf(m4a, m4a_len, "%s/" HLS_ATRANS_SUBDIR "/%s.m4a",
			     media_dir, hex);
	if (hdr)
		lws_snprintf(hdr, hdr_len, "%s/" HLS_ATRANS_SUBDIR "/%s.hdr",
			     media_dir, hex);
}

void
lws_hls_atrans_path(struct per_vhost_data__lws_hls *vhd, const char *filename,
		     int audio_idx, char *buf, size_t len)
{
	hls_atrans_paths(vhd->media_dir, filename, audio_idx, buf, len,
			 NULL, 0);
}

/* one .atrans entry as seen by the directory walks below */
struct hls_atrans_ent {
	char	hdr[1024];	/* .hdr path */
	char	m4a[1024];	/* .m4a path */
	char	filename[256];	/* who it was built from */
	int	audio_idx;
	int64_t size;		/* of the .m4a */
	time_t	used;		/* .hdr mtime, the LRU clock */
};

/* state for a walk over .atrans: read one entry's header, or collect them */
struct hls_atrans_walk {
	char	dirpath[1024];	/* the .atrans dir being walked */
	const char *media_dir;
	const char *match;		/* collect: filename to match */
	struct hls_atrans_ent found;	/* match mode: was ->filled */
	struct hls_atrans_ent *ents;	/* collect mode: growable array */
	size_t n, cap;
	int64_t total;
};

/*
 * Read and validate one shadow pair's header: it must be ours, name a valid
 * media name (subdirectories allowed, see hls_media_name_valid()) that still
 * exists at the recorded size and mtime, and the shadow media itself must be
 * there, and not older than the media.  Returns 0 if so, else 1 (stale, orphaned or unreadable: the caller
 * removes it).
 */
static int
hls_atrans_ent_fill(struct hls_atrans_ent *e, const char *media_dir,
		    const char *dirpath, const char *name)
{
	struct hls_atrans_hdr ah;
	struct stat st;
	size_t nl = strlen(name);
	int fd, n;

	if (nl < 5 || strcmp(name + nl - 4, ".hdr"))
		return -1;

	lws_snprintf(e->hdr, sizeof(e->hdr), "%s/%s", dirpath, name);
	lws_snprintf(e->m4a, sizeof(e->m4a), "%.*s.m4a",
		     (int)(strlen(e->hdr) - 4), e->hdr);

	fd = open(e->hdr, O_RDONLY);
	if (fd < 0)
		return -1;
	n = (int)read(fd, &ah, sizeof(ah));
	close(fd);

	if (n != (int)sizeof(ah) ||
	    memcmp(ah.magic, HLS_ATRANS_MAGIC, sizeof(ah.magic)) ||
	    ah.version != HLS_ATRANS_VERSION ||
	    !memchr(ah.filename, '\0', sizeof(ah.filename)) ||
	    !hls_media_name_valid(ah.filename, strlen(ah.filename)))
		return 1;

	if (stat(e->m4a, &st) || st.st_size < 8)
		return 1;

	{
		char mpath[1024];
		struct stat mst;

		lws_snprintf(mpath, sizeof(mpath), "%s/%s", media_dir,
			     ah.filename);
		if (stat(mpath, &mst))
			return 1;

		/*
		 * ...and the shadow is not older than the media: it was
		 * written from the media, so a shadow older than it was
		 * made from something else, whatever the header says
		 */
		if ((int64_t)mst.st_size != ah.size ||
		    (int64_t)mst.st_mtime != ah.mtime ||
		    st.st_mtime < mst.st_mtime)
			return 1;
	}

	lws_strncpy(e->filename, ah.filename, sizeof(e->filename));
	e->audio_idx = (int)ah.audio_idx;
	/* the shadow's own size and age, not the media's: see the sweep */
	e->size = (int64_t)st.st_size;
	e->used = st.st_mtime;
	if (!stat(e->hdr, &st))
		e->used = st.st_mtime; /* the LRU clock: see lookup() */

	return 0;
}

/* vhd->lock held */
static struct hls_atrans_job *
hls_atrans_job_find(struct per_vhost_data__lws_hls *vhd, const char *filename,
		     int audio_idx)
{
	if (vhd->atrans_running &&
	    !strcmp(vhd->atrans_running->filename, filename) &&
	    vhd->atrans_running->audio_idx == audio_idx)
		return vhd->atrans_running;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->atrans_jobs)) {
		struct hls_atrans_job *j = lws_container_of(d,
						struct hls_atrans_job, list);

		if (!strcmp(j->filename, filename) &&
		    j->audio_idx == audio_idx)
			return j;
	} lws_end_foreach_dll(d);

	return NULL;
}

/* vhd->lock held: drop recent results old enough to be worth retrying */
static void
hls_atrans_recent_expire(struct per_vhost_data__lws_hls *vhd)
{
	lws_usec_t now = lws_now_usecs();

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->atrans_recent)) {
		struct hls_atrans_job *j = lws_container_of(d,
						struct hls_atrans_job, list);

		if (now - j->finished < HLS_ATRANS_RETRY_US)
			continue;
		lws_dll2_remove(&j->list);
		free(j);
	} lws_end_foreach_dll_safe(d, d1);
}

/* vhd->lock held */
static struct hls_atrans_job *
hls_atrans_recent_find(struct per_vhost_data__lws_hls *vhd,
		       const char *filename, int audio_idx)
{
	hls_atrans_recent_expire(vhd);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->atrans_recent)) {
		struct hls_atrans_job *j = lws_container_of(d,
						struct hls_atrans_job, list);

		if (!strcmp(j->filename, filename) &&
		    (audio_idx < 0 || j->audio_idx == audio_idx))
			return j;
	} lws_end_foreach_dll(d);

	return NULL;
}

/* vhd->lock held: make sure a build of (filename, audio_idx) is queued or
 * running */
static struct hls_atrans_job *
hls_atrans_job_ensure(struct per_vhost_data__lws_hls *vhd, const char *filename,
		      int audio_idx)
{
	struct hls_atrans_job *j = hls_atrans_job_find(vhd, filename, audio_idx);

	if (j)
		return j;

	j = calloc(1, sizeof(*j));
	if (!j)
		return NULL;
	lws_strncpy(j->filename, filename, sizeof(j->filename));
	j->audio_idx = audio_idx;
	lws_dll2_add_tail(&j->list, &vhd->atrans_jobs);
	pthread_cond_signal(&vhd->atrans_cond);

	lwsl_notice("HLS-ATRANS: %s:%d: shadow build queued\n", filename,
		    audio_idx);

	return j;
}

/*
 * Tasks parked behind this build whose need the coverage has reached (or
 * all of them, when done) go back to the head of the worker's queue, in
 * arrival order, ahead of newer work.  Takes vhd->lock itself.
 */
static void
hls_atrans_unpark(struct per_vhost_data__lws_hls *vhd, const char *filename,
		  int audio_idx, int64_t covered, int done)
{
	lws_dll2_owner_t mine;
	int n = 0;

	memset(&mine, 0, sizeof(mine));

	pthread_mutex_lock(&vhd->lock);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->parked)) {
		struct hls_task *t = lws_container_of(d, struct hls_task, list);

		if (t->atrans_audio_idx != audio_idx ||
		    strcmp(t->filename, filename))
			continue;
		if (!done && t->atrans_need_us > covered)
			continue;
		lws_dll2_remove(&t->list);
		if (!t->pss) {
			/* detached while parked: nobody wants it */
			lws_hls_task_free(t);
			continue;
		}
		t->state = HLS_TASK_PENDING;
		t->atrans_audio_idx = -1;
		lws_dll2_add_tail(&t->list, &mine);
		n++;
	} lws_end_foreach_dll_safe(d, d1);

	if (!n) {
		pthread_mutex_unlock(&vhd->lock);
		return;
	}

	while (lws_dll2_get_head(&vhd->tasks)) {
		struct hls_task *t = lws_container_of(
				lws_dll2_get_head(&vhd->tasks),
				struct hls_task, list);

		lws_dll2_remove(&t->list);
		lws_dll2_add_tail(&t->list, &mine);
	}
	while (lws_dll2_get_head(&mine)) {
		struct hls_task *t = lws_container_of(lws_dll2_get_head(&mine),
						      struct hls_task, list);

		lws_dll2_remove(&t->list);
		lws_dll2_add_tail(&t->list, &vhd->tasks);
	}

	pthread_cond_signal(&vhd->cond);
	pthread_mutex_unlock(&vhd->lock);

	lwsl_notice("HLS-ATRANS: %s:%d: %d parked task(s) requeued\n",
		    filename, audio_idx, n);
}

/*
 * vhd->lock held: is the shadow wait recorded on this task already
 * satisfied?  The atrans thread can complete a whole build in the window
 * between the task being flagged for parking and actually reaching
 * vhd->parked, so lws_hls_task_park() re-checks rather than sleep through
 * a wakeup that already came and went.
 */
int
lws_hls_atrans_wait_done(struct per_vhost_data__lws_hls *vhd,
			 const char *filename, int audio_idx, int64_t need_us)
{
	struct hls_atrans_job *j = hls_atrans_job_find(vhd, filename, audio_idx);

	if (j)
		return j->covered_us >= need_us;

	j = hls_atrans_recent_find(vhd, filename, audio_idx);

	/* a success is on disk (covered INT64_MAX when it finished) */
	return j && !j->failed;
}

enum hls_atrans_state
lws_hls_atrans_lookup(struct per_vhost_data__lws_hls *vhd, const char *filename,
		      int audio_idx, int64_t *covered_us)
{
	struct hls_atrans_walk w;
	char m4a[1024], hdr[1024];
	enum hls_atrans_state ret = HLS_ATRANS_NONE;

	pthread_mutex_lock(&vhd->lock);

	if (hls_atrans_job_find(vhd, filename, audio_idx)) {
		*covered_us = hls_atrans_job_find(vhd, filename,
						  audio_idx)->covered_us;
		pthread_mutex_unlock(&vhd->lock);

		return HLS_ATRANS_RUNNING;
	}

	{
		struct hls_atrans_job *j = hls_atrans_recent_find(vhd, filename,
								 audio_idx);

		if (j && j->failed) {
			pthread_mutex_unlock(&vhd->lock);

			return HLS_ATRANS_FAILED;
		}
		/* a success is on disk: the check below finds it */
	}

	pthread_mutex_unlock(&vhd->lock);

	hls_atrans_paths(vhd->media_dir, filename, audio_idx,
			 m4a, sizeof(m4a), hdr, sizeof(hdr));
	memset(&w, 0, sizeof(w));
	hls_atrans_dir(vhd->media_dir, w.dirpath, sizeof(w.dirpath));
	if (!hls_atrans_ent_fill(&w.found, vhd->media_dir, w.dirpath,
				 strrchr(hdr, '/') + 1) &&
	    !strcmp(w.found.filename, filename) &&
	    w.found.audio_idx == audio_idx) {
		*covered_us = INT64_MAX;

		/* keep the sweep's oldest-first eviction fair */
		utimensat(AT_FDCWD, hdr, NULL, 0);

		return HLS_ATRANS_READY;
	}

	/* stale or orphaned: nothing will finish it */
	if (unlink(hdr) != -1 || unlink(m4a) != -1)
		lwsl_notice("HLS-ATRANS: %s:%d: dropped stale shadow\n",
			    filename, audio_idx);

	pthread_mutex_lock(&vhd->lock);
	if (!hls_atrans_job_ensure(vhd, filename, audio_idx))
		ret = HLS_ATRANS_FAILED;
	pthread_mutex_unlock(&vhd->lock);

	return ret;
}

int
lws_hls_atrans_defer(struct per_vhost_data__lws_hls *vhd, const char *filename,
		     int audio_idx, int64_t need_us, volatile int *cancel)
{
	struct hls_task *t;
	struct hls_atrans_job *j;
	int park = 0;

	pthread_mutex_lock(&vhd->lock);

	t = vhd->running;
	if (!t)
		goto unlock;

	j = hls_atrans_job_find(vhd, filename, audio_idx);
	if (!j) {
		/*
		 * The build finished (or was never started) between the
		 * caller's lookup and now: if it is on disk the caller will
		 * use it next time around, and if it failed recently there is
		 * no point parking behind it
		 */
		if (hls_atrans_recent_find(vhd, filename, audio_idx))
			/* failed lately: no point parking behind it.  Or it
			 * just succeeded between the caller's lookup and
			 * now, and this build takes the inline path anyway */
			goto unlock;
		j = hls_atrans_job_ensure(vhd, filename, audio_idx);
		if (!j)
			goto unlock;
	}

	/* the coverage estimate raced the caller: nothing to wait for */
	if (j->covered_us < need_us) {
		t->parked = 1;
		t->atrans_audio_idx = audio_idx;
		t->atrans_need_us = need_us;
		park = 1;
	}

unlock:
	pthread_mutex_unlock(&vhd->lock);

	if (!park)
		return 0;

	/*
	 * Make the body builder unwind as if the client had gone; the worker
	 * sorts out which it really was, under the lock, from t->pss
	 */
	if (cancel)
		*cancel = 1;

	return 1;
}

/*
 * write the provenance header beside a completed shadow, rename into place.
 * st0 is the media file as it was when the transcode started: if it is not
 * that any more, the shadow is of something else (or of however much of it
 * had arrived) and gets no header.
 */
static int
hls_atrans_hdr_write(const char *media_dir, const char *filename,
		     int audio_idx, const struct stat *st0)
{
	struct hls_atrans_hdr ah;
	char hdr[1024], tmp[1100], path[1024];
	struct stat st;
	int fd;

	memset(&ah, 0, sizeof(ah));
	memcpy(ah.magic, HLS_ATRANS_MAGIC, sizeof(ah.magic));
	ah.version = HLS_ATRANS_VERSION;
	ah.audio_idx = (uint32_t)audio_idx;
	lws_strncpy(ah.filename, filename, sizeof(ah.filename));

	lws_snprintf(path, sizeof(path), "%s/%s", media_dir, filename);
	if (stat(path, &st) || st.st_size != st0->st_size ||
	    st.st_mtime != st0->st_mtime)
		return -1;
	ah.size = (int64_t)st.st_size;
	ah.mtime = (int64_t)st.st_mtime;

	hls_atrans_paths(media_dir, filename, audio_idx, NULL, 0,
			 hdr, sizeof(hdr));
	lws_snprintf(tmp, sizeof(tmp), "%s.tmp", hdr);

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	if (write(fd, &ah, sizeof(ah)) != (ssize_t)sizeof(ah)) {
		close(fd);
		unlink(tmp);
		return -1;
	}
	close(fd);
	if (rename(tmp, hdr)) {
		unlink(tmp);
		return -1;
	}

	return 0;
}

/*
 * Transcode stream audio_idx of one media file into its shadow.  Runs on
 * the atrans thread.  Returns 0 if the shadow is there and valid, -1 if not.
 */
static int
hls_atrans_build(struct per_vhost_data__lws_hls *vhd,
		 struct hls_atrans_job *j)
{
	char filepath[1024], m4a[1024], hdr[1024], dir[1024];
	struct hls_audio_transcoder *tx = NULL;
	AVFormatContext *in_ctx = NULL, *out_ctx = NULL;
	AVDictionary *opts = NULL;
	AVStream *out_stream;
	int64_t dur_us = 0, last_pub_s = -1;
	int audio_idx = j->audio_idx;
	enum hls_media_state ms;
	struct stat st0;
	int ret = -1;

	/* never a shadow of a file that is not all there, see hls-media.c */
	ms = lws_hls_media_state(vhd->media_dir, j->filename, &st0);
	if (ms != HLS_MEDIA_COMPLETE) {
		lwsl_notice("HLS-ATRANS: %s:%d: %s, not transcoding\n",
			    j->filename, audio_idx,
			    lws_hls_media_state_name(ms));
		return -1;
	}

	lws_snprintf(filepath, sizeof(filepath), "%s/%s", vhd->media_dir,
		     j->filename);

	hls_atrans_dir(vhd->media_dir, dir, sizeof(dir));
	if (mkdir(dir, 0700) && errno != EEXIST) {
		lwsl_warn("%s: cannot create %s: %s\n", __func__, dir,
			  strerror(errno));
		return -1;
	}
	hls_atrans_paths(vhd->media_dir, j->filename, audio_idx,
			 m4a, sizeof(m4a), hdr, sizeof(hdr));

	if (avformat_open_input(&in_ctx, filepath, NULL, NULL) < 0)
		return -1;
	if (avformat_find_stream_info(in_ctx, NULL) < 0)
		goto out;
	if ((unsigned int)audio_idx >= in_ctx->nb_streams ||
	    in_ctx->streams[audio_idx]->codecpar->codec_type !=
							AVMEDIA_TYPE_AUDIO ||
	    !lws_hls_needs_audio_transcode(
			in_ctx->streams[audio_idx]->codecpar->codec_id)) {
		/* the file changed under us, or never needed it */
		lwsl_notice("HLS-ATRANS: %s:%d: no longer transcodable\n",
			    j->filename, audio_idx);
		goto out;
	}

	tx = lws_hls_audio_tx_create(in_ctx, audio_idx);
	if (!tx)
		goto out;

	if (avformat_alloc_output_context2(&out_ctx, NULL, NULL, m4a) < 0 ||
	    !out_ctx)
		goto out;
	out_stream = avformat_new_stream(out_ctx, NULL);
	if (!out_stream)
		goto out;
	avcodec_parameters_from_context(out_stream->codecpar, tx->enc_ctx);
	out_stream->codecpar->codec_tag = 0;
	out_stream->time_base = (AVRational){ 1, tx->enc_ctx->sample_rate };

	if (avio_open(&out_ctx->pb, m4a, AVIO_FLAG_WRITE) < 0)
		goto out;

	/*
	 * Fragmented, so a segment build can read what has been written so
	 * far while the transcode continues towards the end of the file.
	 */
	av_dict_set(&opts, "movflags",
		    "empty_moov+default_base_moof+frag_discont", 0);
	av_dict_set_int(&opts, "frag_duration", HLS_ATRANS_FRAG_US, 0);

	if (avformat_write_header(out_ctx, &opts) < 0)
		goto out;

	dur_us = in_ctx->duration;
	if (dur_us <= 0 && in_ctx->streams[audio_idx]->duration > 0)
		dur_us = av_rescale_q(in_ctx->streams[audio_idx]->duration,
				      in_ctx->streams[audio_idx]->time_base,
				      AV_TIME_BASE_Q);

	{
		AVPacket pkt;

		while (av_read_frame(in_ctx, &pkt) >= 0) {
			int64_t pts_us, pub_s;

			if (pkt.stream_index != audio_idx) {
				av_packet_unref(&pkt);
				continue;
			}
			pts_us = av_rescale_q(pkt.pts != AV_NOPTS_VALUE ?
					      pkt.pts : pkt.dts,
					      in_ctx->streams[audio_idx]->time_base,
					      AV_TIME_BASE_Q);

			if (lws_hls_audio_tx_packet(in_ctx, out_ctx, tx, &pkt,
						    0, 0, NULL, NULL, NULL,
						    NULL, NULL, NULL, 0)) {
				lwsl_err("HLS-ATRANS: %s:%d: muxer refused "
					 "output\n", j->filename, audio_idx);
				av_packet_unref(&pkt);
				goto out;
			}
			av_packet_unref(&pkt);

			/*
			 * Publish the coverage once a second: push what the
			 * muxer has out of its avio buffer first, and trail
			 * the cursor by the fragment / decoder latency, so
			 * readers are only ever told about data that is
			 * really on disk.  Waking parked tasks once a second
			 * is plenty.
			 */
			if (pts_us / LWS_US_PER_SEC != last_pub_s) {
				int64_t cov;

				avio_flush(out_ctx->pb);

				cov = pts_us > HLS_ATRANS_COVER_LAG_US ?
				      pts_us - HLS_ATRANS_COVER_LAG_US : 0;
				pthread_mutex_lock(&vhd->lock);
				j->covered_us = cov;
				if (dur_us > 0)
					j->pct = (int)(cov * 100 / dur_us);
				pthread_mutex_unlock(&vhd->lock);

				pub_s = cov / LWS_US_PER_SEC;
				if (pub_s != last_pub_s) {
					last_pub_s = pub_s;
					hls_atrans_unpark(vhd, j->filename,
							  audio_idx, cov, 0);
				}
			}

			if (vhd->thread_exit)
				goto out;
		}

		lws_hls_audio_tx_flush(out_ctx, tx, 0, NULL, NULL, NULL, NULL,
				       NULL, NULL, 0);
	}

	av_write_trailer(out_ctx);

	/* the media changing under us invalidates the whole shadow */
	if (hls_atrans_hdr_write(vhd->media_dir, j->filename, audio_idx,
				 &st0)) {
		lwsl_notice("HLS-ATRANS: %s:%d: media changed, shadow "
			    "dropped\n", j->filename, audio_idx);
		goto out;
	}

	ret = 0;

out:
	av_dict_free(&opts);
	if (out_ctx) {
		if (out_ctx->pb)
			avio_closep(&out_ctx->pb);
		avformat_free_context(out_ctx);
	}
	if (tx)
		lws_hls_audio_tx_free(tx);
	avformat_close_input(&in_ctx);

	if (ret)
		/* an unfinished shadow is useless: do not leave it around */
		unlink(m4a);

	return ret;
}

void *
lws_hls_atrans_thread(void *d)
{
	struct per_vhost_data__lws_hls *vhd =
			(struct per_vhost_data__lws_hls *)d;

	while (1) {
		struct hls_atrans_job *j;
		int failed, arriving;

		pthread_mutex_lock(&vhd->lock);
		while (!vhd->thread_exit &&
		       !lws_dll2_get_head(&vhd->atrans_jobs))
			pthread_cond_wait(&vhd->atrans_cond, &vhd->lock);
		if (vhd->thread_exit) {
			pthread_mutex_unlock(&vhd->lock);
			break;
		}
		j = lws_container_of(lws_dll2_get_head(&vhd->atrans_jobs),
				     struct hls_atrans_job, list);
		lws_dll2_remove(&j->list);
		vhd->atrans_running = j;
		pthread_mutex_unlock(&vhd->lock);

		lwsl_notice("HLS-ATRANS: %s:%d: transcoding shadow\n",
			    j->filename, j->audio_idx);
		failed = hls_atrans_build(vhd, j) < 0;
		/*
		 * Failing because the file is not all there yet is not worth
		 * remembering: once it is, the next ask should build it
		 */
		arriving = failed && lws_hls_media_state(vhd->media_dir,
					j->filename, NULL) != HLS_MEDIA_COMPLETE;
		lwsl_notice("HLS-ATRANS: %s:%d: shadow %s\n", j->filename,
			    j->audio_idx, arriving ? "skipped, file incomplete" :
					(failed ? "FAILED" : "ready"));

		pthread_mutex_lock(&vhd->lock);
		vhd->atrans_running = NULL;
		j->failed = failed;
		j->finished = lws_now_usecs();
		j->pct = 100;
		j->covered_us = failed ? 0 : INT64_MAX;
		/*
		 * Otherwise kept on recent whether it worked or not: a
		 * success is on disk and never consults this, a failure must
		 * not have tasks parked behind it again until the retry
		 * window.  Tasks parked behind an incomplete file are refused
		 * by the worker when they run again.
		 */
		if (!arriving)
			lws_dll2_add_tail(&j->list, &vhd->atrans_recent);
		pthread_mutex_unlock(&vhd->lock);

		hls_atrans_unpark(vhd, j->filename, j->audio_idx,
				  INT64_MAX, 1);
		if (arriving)
			free(j);

		/* the status endpoint may have someone polling */
		lws_cancel_service(vhd->context);
	}

	return NULL;
}

void
lws_hls_atrans_destroy(struct per_vhost_data__lws_hls *vhd)
{
	while (lws_dll2_get_head(&vhd->atrans_jobs)) {
		struct hls_atrans_job *j = lws_container_of(
				lws_dll2_get_head(&vhd->atrans_jobs),
				struct hls_atrans_job, list);

		lws_dll2_remove(&j->list);
		free(j);
	}
	while (lws_dll2_get_head(&vhd->atrans_recent)) {
		struct hls_atrans_job *j = lws_container_of(
				lws_dll2_get_head(&vhd->atrans_recent),
				struct hls_atrans_job, list);

		lws_dll2_remove(&j->list);
		free(j);
	}
}

/* lws_dir() callback: fill walk->found for the entry matching ->match */
static int
hls_atrans_match_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct hls_atrans_walk *w = (struct hls_atrans_walk *)user;
	struct hls_atrans_ent e;

	if (lde->type != LDOT_FILE || !w->media_dir)
		return 0;
	if (hls_atrans_ent_fill(&e, w->media_dir, dirpath, lde->name))
		return 0;
	if (strcmp(e.filename, w->match))
		return 0;

	w->found = e;

	/* stop the walk: lws_dir() then returns 0 */
	return 1;
}

/*
 * The media file is going: remove every stream's shadow for it from disk.
 * Shadows are keyed by a hash, so finding them means walking the small
 * headers in .atrans.
 */
void
lws_hls_atrans_unlink(const char *media_dir, const char *filename)
{
	struct hls_atrans_walk w;
	char dir[1024];

	memset(&w, 0, sizeof(w));
	w.media_dir = media_dir;
	w.match = filename;

	hls_atrans_dir(media_dir, dir, sizeof(dir));
	if (access(dir, F_OK))
		return;

	while (1) {
		lws_dir(dir, &w, hls_atrans_match_cb);
		if (!w.found.hdr[0])
			break;
		unlink(w.found.m4a);
		unlink(w.found.hdr);
		lwsl_notice("HLS-ATRANS: %s: removed shadow %s\n", filename,
			    w.found.hdr);
		memset(&w.found, 0, sizeof(w.found));
	}
}

void
lws_hls_atrans_forget(struct per_vhost_data__lws_hls *vhd, const char *filename)
{
	pthread_mutex_lock(&vhd->lock);
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->atrans_jobs)) {
		struct hls_atrans_job *j = lws_container_of(d,
						struct hls_atrans_job, list);

		if (!strcmp(j->filename, filename)) {
			lws_dll2_remove(&j->list);
			free(j);
		}
	} lws_end_foreach_dll_safe(d, d1);
	pthread_mutex_unlock(&vhd->lock);

	lws_hls_atrans_unlink(vhd->media_dir, filename);
}

/* lws_dir() callback: collect the valid entries, drop the invalid ones */
static int
hls_atrans_sweep_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct hls_atrans_walk *w = (struct hls_atrans_walk *)user;
	struct hls_atrans_ent e;
	char path[1024];
	size_t nl;

	if (lde->type != LDOT_FILE)
		return 0;

	nl = strlen(lde->name);

	/* an unfinished hdr write: nothing will complete it */
	if (nl > 4 && !strcmp(lde->name + nl - 4, ".tmp")) {
		lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
		unlink(path);
		return 0;
	}


	switch (hls_atrans_ent_fill(&e, w->media_dir, dirpath, lde->name)) {
	case 0:
		break;
	case -1:
		/* not a .hdr: shadow media without its header is an orphan */
		if (nl > 4 && !strcmp(lde->name + nl - 4, ".m4a")) {
			lws_snprintf(e.hdr, sizeof(e.hdr), "%s/%.*s.hdr",
				     dirpath, (int)(nl - 4), lde->name);
			if (access(e.hdr, F_OK)) {
				lws_snprintf(e.m4a, sizeof(e.m4a), "%s/%s",
					     dirpath, lde->name);
				lwsl_notice("HLS-ATRANS: sweep: removing "
					    "orphan %s\n", e.m4a);
				unlink(e.m4a);
			}
		}
		return 0;
	default:
		lwsl_notice("HLS-ATRANS: sweep: removing %s/%s (stale)\n",
			    dirpath, lde->name);
		unlink(e.hdr);
		unlink(e.m4a);
		return 0;
	}

	w->total += e.size;
	if (w->n < w->cap) {
		w->ents[w->n++] = e;
		return 0;
	}
	if (w->cap < 512) {
		size_t nc = w->cap ? w->cap * 2 : 32;
		struct hls_atrans_ent *ne = realloc(w->ents,
						nc * sizeof(*ne));

		if (!ne)
			return 0;	/* over-counting only weakens the
					 * cap, it is not an error */
		w->ents = ne;
		w->cap = nc;
		w->ents[w->n++] = e;
	}

	return 0;
}

/* oldest "used" first: the first to be evicted by the size cap */
static int
hls_atrans_ent_cmp(const void *a, const void *b)
{
	const struct hls_atrans_ent *ea = a, *eb = b;

	if (ea->used != eb->used)
		return ea->used < eb->used ? -1 : 1;

	return 0;
}

void
lws_hls_atrans_sweep(struct per_vhost_data__lws_hls *vhd)
{
	struct hls_atrans_walk w;
	char dir[1024];
	size_t i;

	memset(&w, 0, sizeof(w));
	w.media_dir = vhd->media_dir;

	hls_atrans_dir(vhd->media_dir, dir, sizeof(dir));
	if (access(dir, F_OK)) {
		free(w.ents);
		return;
	}

	lws_dir(dir, &w, hls_atrans_sweep_cb);

	if (!w.n)
		return;

	/* size cap: evict least-recently-used completed shadows first */
	if (w.total <= HLS_ATRANS_MAX_BYTES) {
		free(w.ents);
		return;
	}

	qsort(w.ents, w.n, sizeof(*w.ents), hls_atrans_ent_cmp);

	for (i = 0; i < w.n && w.total > HLS_ATRANS_MAX_BYTES; i++) {
		lwsl_notice("HLS-ATRANS: sweep: over cap, removing %s\n",
			    w.ents[i].hdr);
		if (!unlink(w.ents[i].m4a))
			w.total -= w.ents[i].size;
		unlink(w.ents[i].hdr);
	}


	free(w.ents);
}

/*
 * Event loop: the atrans half of the /index/<file> status JSON.  This is
 * peek-only: it does not queue anything, since whether a file's audio needs
 * transcoding at all is only known once something has opened it.
 */
int
lws_hls_atrans_status_json(struct per_vhost_data__lws_hls *vhd,
			   const char *filename, char *buf, size_t len)
{
	const char *st = "none";
	struct hls_atrans_job *j = NULL;
	int pct = 0;

	pthread_mutex_lock(&vhd->lock);

	if (vhd->atrans_running &&
	    !strcmp(vhd->atrans_running->filename, filename)) {
		j = vhd->atrans_running;
		pct = j->pct;
	} else {
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&vhd->atrans_jobs)) {
			struct hls_atrans_job *jj = lws_container_of(d,
						struct hls_atrans_job, list);

			if (!strcmp(jj->filename, filename)) {
				j = jj;
				pct = jj->pct;
				break;
			}
		} lws_end_foreach_dll(d);
	}

	if (j) {
		st = "running";
	} else {
		struct hls_atrans_job *rj = hls_atrans_recent_find(vhd, filename,
								 -1);

		/* a success is on disk: the check below reports it */
		if (rj && rj->failed)
			st = "failed";
	}

	pthread_mutex_unlock(&vhd->lock);

	if (!j && !strcmp(st, "none")) {
		/* a shadow from an earlier run counts as ready */
		struct hls_atrans_walk w;
		char dir[1024];

		memset(&w, 0, sizeof(w));
		w.media_dir = vhd->media_dir;
		w.match = filename;
		hls_atrans_dir(vhd->media_dir, dir, sizeof(dir));
		if (!access(dir, F_OK)) {
			lws_dir(dir, &w, hls_atrans_match_cb);
			if (w.found.hdr[0])
				st = "ready";
		}
	}

	return lws_snprintf(buf, len, ",\"atrans\":\"%s\",\"atrans_progress\":%d",
			    st, pct);
}
