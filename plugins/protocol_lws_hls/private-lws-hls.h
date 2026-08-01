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
 */

#if !defined (LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif

#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/avutil.h>
#include <libavutil/audio_fifo.h>
#include <libswscale/swscale.h>
#include <libswresample/swresample.h>

#include <pthread.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

/*
 * Segment duration in seconds. Shared by the A/V playlist generator
 * (hls-av.c) and the subtitle playlist generator (hls-sub.c) so that
 * subtitle segments line up with the A/V timeline.
 */
#define HLS_SEGMENT_DUR 10

struct thumb_task {
	struct thumb_task *next;
	char filename[256];
};

struct thumb_cache {
	struct thumb_cache *next;
	char filename[256];
	uint8_t *data;
	size_t len;
};

struct per_vhost_data__lws_hls {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	
	const char *media_dir; /* configured via pvo */

	/* Thumbnail worker thread */
	pthread_t thumb_thread;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int thread_exit;
	
	struct thumb_task *task_head;
	struct thumb_task *task_tail;
	char current_task_filename[256];
	
	struct thumb_cache *cache_head;
	int cache_count;
	
	struct hls_file_index *index_head;
	struct per_session_data__lws_hls *pss_list; /* active sessions */

	/* WebVTT subtitle cue cache (per media file + track id) */
	struct hls_sub_cache *sub_cache_head;
	int sub_cache_count;
	pthread_mutex_t sub_lock;

#if defined(LWS_WITH_STUB)
	struct lws_stub_manager *stub_mgr;
#endif
	int has_jwk;
	struct lws_jwk jwk;
};

struct hls_index_entry {
	int64_t pos;
	int64_t timestamp;
	int64_t dts;
	int min_distance;
	int size;
	int flags;
};

struct hls_file_index {
	struct hls_file_index *next;
	char filename[256];
	int video_idx;
	int count;
	struct hls_index_entry *entries;
};

/* Per-segment boundaries, computed from the input video's keyframe index.
 * Defined in hls-av.c, shared with hls-sub.c for subtitle alignment. */
struct hls_segment_info {
	int64_t start_pts;
	int64_t end_pts;
	int64_t seek_pts;
	double duration_sec;
};

/* --- WebVTT subtitle support (hls-sub.c) --- */

enum hls_sub_kind {
	HLS_SUB_EMBEDDED,
	HLS_SUB_SIDECAR,
};

/* Description of one available subtitle track for a media file.
 * ids are stable per-file: "eN" for the Nth embedded text stream,
 * "sN" for the Nth sidecar file (sorted alphabetically). */
struct hls_sub_track {
	enum hls_sub_kind kind;
	char id[8];          /* "eN" or "sN" */
	char lang[16];       /* BCP47-ish: "en", "pt-BR", or "und" */
	char name[64];       /* human-readable, e.g. "English" */
	int  stream_index;   /* embedded only: AVStream index */
	char path[256];      /* sidecar only: filename relative to media_dir */
	int  is_vtt;         /* sidecar only: 1=.vtt, 0=.srt */
};

/* One decoded subtitle cue. text is plain (LF-separated), WebVTT-safe. */
struct hls_webvtt_cue {
	double start;        /* seconds from media start */
	double end;
	char  *text;
};

/* Cached decoded cues for one (filename, track id) pair. */
struct hls_sub_cache {
	struct hls_sub_cache *next;
	char key[280];               /* "<filename>|<trackid>" */
	struct hls_webvtt_cue *cues;
	int n_cues;
};

struct per_session_data__lws_hls {
	struct per_session_data__lws_hls *pss_list;
	struct lws *wsi;
	uint8_t *segment_buf;
	size_t segment_len;
	size_t segment_pos;
	
	/* Thumbnail async state */
	int waiting_for_thumbnail;
	char thumb_filename[256];
	
	int has_star_grant;

	/* stub lejp parsing */
	struct lejp_ctx jctx;
	int parser_valid;
};

/* hls-av.c */
void *
lws_hls_thumbnail_worker(void *d);

int
lws_hls_serve_thumbnail(struct lws *wsi, const char *media_dir, const char *filename);

int
lws_hls_serve_dir(struct lws *wsi, const char *media_dir);

int
lws_hls_serve_init(struct lws *wsi, const char *media_dir, const char *filename);

/* A/V media playlist (referenced as a variant from the master playlist
 * when subtitles exist, or served directly otherwise). */
int
lws_hls_serve_manifest(struct lws *wsi, const char *media_dir, const char *filename);

int
lws_hls_serve_segment(struct lws *wsi, const char *media_dir, const char *filename, int segment_idx);

/* Compute segment [start_pts, end_pts] / duration for the target segment
 * index of a media file, plus the total segment count. Used by both the
 * A/V and subtitle playlist generators to keep a shared timeline. */
int
lws_hls_get_segment_info(struct per_vhost_data__lws_hls *vhd, const char *filename,
			 AVFormatContext *in_ctx, int video_idx, int target_seg_idx,
			 struct hls_segment_info *out_info, int *out_total_segments);

/* hls-sub.c */

/* Discover every usable subtitle track for a media file: embedded text
 * streams first (ordered by stream index), then sibling .srt/.vtt sidecars
 * (sorted alphabetically). Returns a malloc'd array and count in *out_count;
 * caller frees with lws_hls_free_tracks(). Returns NULL / 0 if none. */
struct hls_sub_track *
lws_hls_discover_tracks(const char *media_dir, const char *filename, int *out_count);

void
lws_hls_free_tracks(struct hls_sub_track *tracks, int count);

/* Resolve a track id ("eN"/"sN") within a discovered set; returns index
 * into tracks[] or -1 if not found. */
int
lws_hls_find_track(struct hls_sub_track *tracks, int count, const char *trackid);

/* Master playlist dispatcher: if the file has subtitle tracks, emit a
 * master playlist (one #EXT-X-STREAM-INF + per-track #EXT-X-MEDIA
 * TYPE=SUBTITLES); otherwise delegate to the plain A/V media playlist. */
int
lws_hls_serve_stream(struct lws *wsi, const char *media_dir, const char *filename);

/* Subtitle media playlist for one track. */
int
lws_hls_serve_sub_playlist(struct lws *wsi, struct per_vhost_data__lws_hls *vhd,
			   const char *media_dir, const char *filename,
			   const char *trackid);

/* One WebVTT segment: cues whose window overlaps [seg_start, seg_end),
 * rebased to segment-relative timestamps. */
int
lws_hls_serve_sub_segment(struct lws *wsi, struct per_vhost_data__lws_hls *vhd,
			  const char *media_dir, const char *filename,
			  const char *trackid, int seg_idx);
