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

#if !defined(PRIVATE_LWS_HLS_H)
#define PRIVATE_LWS_HLS_H

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
#include <stdarg.h>
#include <stdio.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

/*
 * Clamped-cursor composition helper.  The naive `q += snprintf(q, rem, ...)`
 * pattern advances q by the *would-have-written* length on truncation, so the
 * cursor can pass the end of the buffer and the next `rem = cap - used`
 * underflows to a huge size_t, making the following snprintf write unbounded
 * past the allocation (F-059).  This variant only advances by what actually
 * fit, and holds the cursor still at the end of the buffer instead.
 *
 * Shared by hls-dir.c (directory listing HTML) and hls-sub.c (playlist
 * composition).  q and buf are body-area pointers; cap is the body size.
 */
static inline char *
hls_append_fmt(char *q, char *buf, size_t cap, const char *fmt, ...)
{
	va_list ap;
	size_t used = (size_t)(q - buf);
	size_t rem = (cap > used) ? (cap - used) : 0;
	int n;

	if (rem == 0)
		return q;

	va_start(ap, fmt);
	n = vsnprintf(q, rem, fmt, ap);
	va_end(ap);

	if (n < 0)
		return q; /* encoding error; leave cursor unchanged */
	if ((size_t)n >= rem)
		n = (int)(rem - 1); /* clamp to what actually fit (sans NUL) */

	return q + n;
}

#if defined(LWS_PLUGIN_STATIC)
/* when the plugin sources are folded into another build (api tests), the
 * hosting code needs the callback and the protocol table entry */
int
callback_lws_hls(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len);
#endif

#define LWS_PLUGIN_PROTOCOL_LWS_HLS \
	{ \
		"lws-hls", \
		callback_lws_hls, \
		sizeof(struct per_session_data__lws_hls), \
		1024, \
		0, NULL, 0 \
	}

/*
 * Segment duration in seconds. Shared by the A/V playlist generator
 * (hls-av.c) and the subtitle playlist generator (hls-sub.c) so that
 * subtitle segments line up with the A/V timeline.
 */
#define HLS_SEGMENT_DUR 10

struct thumb_task {
	lws_dll2_t list;	/* vhd->tasks FIFO membership */
	char filename[256];
};

struct thumb_cache {
	lws_dll2_t list;	/* vhd->thumb_cache membership, MRU first */
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

	lws_dll2_owner_t tasks;		/* pending thumbnail work, FIFO */
	char current_task_filename[256];

	lws_dll2_owner_t thumb_cache;	/* finished thumbnails, MRU first */
	int cache_count;

	lws_dll2_owner_t index_list;	/* per-file keyframe index cache */
	lws_dll2_owner_t pss_list; /* active sessions */

	/* WebVTT subtitle cue cache (per media file + track id) */
	lws_dll2_owner_t sub_cache;	/* decoded cue lists, MRU first */
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
	lws_dll2_t list;	/* vhd->index_list membership */
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
	char id[16];          /* "eN" or "sN" */
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
	lws_dll2_t list;	/* vhd->sub_cache membership, MRU first */
	char key[280];               /* "<filename>|<trackid>" */
	struct hls_webvtt_cue *cues;
	int n_cues;
};

struct per_session_data__lws_hls {
	lws_dll2_t pss_list; /* vhd pss_list membership */
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
#endif /* PRIVATE_LWS_HLS_H */
