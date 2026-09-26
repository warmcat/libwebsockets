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
#include <sys/stat.h>
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

/*
 * "../" repeated depth times, for URIs composed into a playlist that lives
 * at /<root>/<media-name-with-any-subdirs>: each '/' in the media name
 * deepens the playlist's own URL by one, so the climb out to the root of
 * the URL space grows with it.  depth >= 1.
 */
static inline void
hls_up_prefix(char *buf, size_t len, int depth)
{
	size_t o = 0;

	while (depth-- > 0 && o + 3 < len) {
		buf[o++] = '.';
		buf[o++] = '.';
		buf[o++] = '/';
	}
	buf[o] = '\0';
}

/*
 * Is [p, p + len) a media name we may act on?  A media name may span
 * subdirectories under media-dir (the listing walks them), so it is a
 * relative path rather than a single component: every '/'-separated
 * component non-empty and neither "." nor "..", and no control characters
 * anywhere (a leading or trailing '/' is an empty component, so those fail
 * too).  Everything that turns a name from outside (a URL, the stub UDS, a
 * cache header read back from disk) into a path under media-dir asks this
 * first.
 */
static inline int
hls_media_name_valid(const char *p, size_t len)
{
	size_t i, cs = 0;

	if (!len)
		return 0;

	for (i = 0; i <= len; i++) {
		char c = (i < len) ? p[i] : '/';

		if (c == '/') {
			size_t cl = i - cs;

			if (!cl || (cl == 1 && p[cs] == '.') ||
			    (cl == 2 && p[cs] == '.' && p[cs + 1] == '.'))
				return 0;
			cs = i + 1;
		} else if ((unsigned char)c < 0x20 || (unsigned char)c == 0x7f)
			return 0;
	}

	return 1;
}

/* how many '/' a media name carries, ie its subdirectory depth */
static inline int
hls_media_depth(const char *filename)
{
	int n = 0;
	const char *p = filename;

	while ((p = strchr(p, '/'))) {
		n++;
		p++;
	}

	return n;
}

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

/*
 * Upper bound on the segment count of any generated playlist.  The count is
 * derived either from the container's keyframe index or from its declared
 * duration, and neither is trustworthy: unclamped, the sizing arithmetic
 * (`total_segments * 128`) overflows int, and the composition loop and its
 * allocation become unbounded.  HLS_MAX_SEGMENTS x HLS_SEGMENT_DUR is over
 * 55 hours of media, ie, well past anything legitimate.
 */
#define HLS_MAX_SEGMENTS 20000

/*
 * Sanity ceiling in seconds for one segment's EXTINF duration.  It is
 * computed from container timestamps scaled by the container's own
 * time_base, so a hostile file can make it astronomically large, and "%f"
 * of such a double is hundreds of characters wide.
 */
#define HLS_MAX_SEG_DUR 86400.0

/*
 * Everything that opens a media file with libavformat runs on the vhost's
 * worker thread, never on the event loop: opening a 10GB MKV, scanning it to
 * build a keyframe index when it has no cues, demuxing a segment, and
 * transcoding its audio all take from tens of milliseconds to minutes, and
 * done synchronously inside LWS_CALLBACK_HTTP they stall every vhost on the
 * context for the duration.
 *
 * The HTTP callback validates the URL, queues an hls_task naming what is
 * wanted, and returns with the transaction pending.  The worker pops tasks
 * FIFO, builds the response body into the task, moves the task to vhd->done
 * and wakes the event loop with lws_cancel_service(); the event loop then
 * hands the body to the waiting session and starts the HTTP response.
 *
 * Thumbnails are the exception in that their result goes into a shared
 * cache rather than to one session, since several sessions typically ask
 * for the same one at once (the directory listing).
 */
enum hls_task_type {
	HLS_TASK_THUMB,		/* result goes into vhd->thumb_cache */
	HLS_TASK_INIT,		/* the rest produce a body for one session */
	HLS_TASK_MANIFEST,
	HLS_TASK_SEGMENT,
	HLS_TASK_STREAM,
	HLS_TASK_SUB_PLAYLIST,
	HLS_TASK_SUB_SEGMENT,
};

enum hls_task_state {
	HLS_TASK_PENDING,	/* on vhd->tasks, not started */
	HLS_TASK_RUNNING,	/* the worker has it */
	HLS_TASK_PARKED,	/* on vhd->parked, waiting for an index */
	HLS_TASK_DONE,		/* on vhd->done, awaiting collection */
};

/* what a task hands back: an HTTP status, and for 200, a body */
struct hls_result {
	uint8_t *body;		/* malloc'd, payload at body + LWS_PRE */
	size_t len;
	const char *content_type;
	int status;		/* HTTP status code */
};

struct hls_task {
	lws_dll2_t list;	/* vhd->tasks (pending) or vhd->done */
	enum hls_task_type type;
	enum hls_task_state state;	/* under vhd->lock */
	char filename[256];
	char trackid[16];
	int segment_idx;

	/*
	 * The session waiting on us, or NULL if it went away first.  Only
	 * the event loop reads or writes this; the worker never looks at it.
	 */
	struct per_session_data__lws_hls *pss;
	/*
	 * Set by the event loop when the session goes away or the vhost is
	 * being destroyed, polled by the worker inside its long loops so it
	 * stops early rather than finishing work nobody will collect.
	 */
	volatile int cancel;
	/*
	 * Set by lws_hls_index_defer() on the worker when the task needs an
	 * index that is not built yet: the worker discards whatever the body
	 * builder produced and parks the task until the indexer is done.
	 */
	int parked;
	/*
	 * Set by lws_hls_atrans_defer() when the task is parked waiting for
	 * the shadow transcode of stream atrans_audio_idx to cover
	 * atrans_need_us of the timeline.  -1 when the task is not parked
	 * behind an audio transcode.
	 */
	int atrans_audio_idx;
	int64_t atrans_need_us;

	struct hls_result r;
};

/*
 * One keyframe index build on the indexer thread.  Lives on vhd->index_jobs
 * until it runs, then on vhd->index_recent for a while so the worker knows
 * not to park tasks behind a build that just failed (or produced nothing
 * cacheable) and would only fail again.
 */
struct hls_index_job {
	lws_dll2_t list;
	char filename[256];
	volatile int pct;	/* scan progress, for the status endpoint */
	int failed;
	lws_usec_t finished;
};

/*
 * One shadow transcode of (media file, audio stream) on the atrans thread.
 * Lives on vhd->atrans_jobs until it runs, then on vhd->atrans_recent for
 * a while so the worker knows not to park tasks behind a build that just
 * failed.  covered_us is how far into the timeline the muxer has flushed:
 * readers may cut segments from the shadow below it (it trails the muxer's
 * internal buffering by a safety margin on purpose), INT64_MAX when the
 * shadow is complete.
 */
struct hls_atrans_job {
	lws_dll2_t list;
	char filename[256];
	int audio_idx;
	volatile int pct;
	int64_t covered_us;	/* under vhd->lock */
	int failed;
	lws_usec_t finished;
};

#define HLS_CANCELLED(c) ((c) && *(c))

/*
 * How long a session waits for its task.  The queue is FIFO through one
 * worker, and the first touch of a large file without cues scans it twice
 * to build the keyframe index, so this has to cover a few of those queued
 * back to back.  A session that times out detaches from its task, which then
 * cancels at the next check.
 */
#define HLS_TASK_TIMEOUT_SECS 300

/*
 * Thumbnails are keyed by file and time: the listing shows the default
 * one (HLS_THUMB_DEFAULT_T, -1 here) for a file the viewer has not started,
 * and one at their resume position for a file they have, so several
 * viewers can each be looking at a different frame of the same file.
 * Times are bucketed by the client (HLS_THUMB_T_BUCKET) to bound this.
 */
#define HLS_THUMB_DEFAULT_T	-1
#define HLS_THUMB_DEFAULT_SECS	10
#define HLS_THUMB_CACHE_CAP	64

struct thumb_cache {
	lws_dll2_t list;	/* vhd->thumb_cache membership, MRU first */
	char filename[256];
	int t;			/* seconds, or HLS_THUMB_DEFAULT_T */
	uint8_t *data;
	size_t len;
};

struct per_vhost_data__lws_hls {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	
	const char *media_dir; /* configured via pvo */

	/*
	 * Where the player page and its assets live, relative to wherever
	 * this protocol's listing is served from, as a pvo-supplied URL
	 * fragment ("..", "hls", "." ...).  It is only ever composed into the
	 * listing's relative links, so it must never be absolute: the whole
	 * app is expected to be reachable behind a reverse proxy that mounts
	 * it at an unknown point of someone else's URL space.
	 */
	char asset_prefix[64];

	/*
	 * Directory the player page and its assets are served from, on this
	 * protocol's own URL space (see hls_serve_asset()): the app is one
	 * flat mount this way, with the listing, the endpoints and the assets
	 * all beside each other.  Configured via pvo, defaulting to
	 * <media-dir>/mount-origin.
	 */
	char www_dir[1024];

	/* worker thread: see enum hls_task_type */
	pthread_t worker_thread;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int thread_exit;

	lws_dll2_owner_t tasks;		/* pending work, FIFO */
	lws_dll2_owner_t done;		/* finished, awaiting collection */
	struct hls_task *running;	/* what the worker has, under lock */
	lws_dll2_owner_t parked;	/* tasks waiting on an index build */

	/*
	 * indexer thread: builds keyframe indexes, so a multi-minute scan of
	 * one file does not stop the worker serving every other file.  All
	 * lists under vhd->lock, index_cond signalled with it held.
	 */
	pthread_t indexer_thread;
	pthread_cond_t index_cond;
	lws_dll2_owner_t index_jobs;	/* pending builds, FIFO */
	struct hls_index_job *index_running;
	lws_dll2_owner_t index_recent;	/* finished builds, see the struct */
	char current_task_filename[256]; /* thumbnail being extracted */
	int current_task_t;		/* ...and at what time, see thumb_cache */

	lws_dll2_owner_t thumb_cache;	/* finished thumbnails, MRU first */
	int cache_count;

	lws_dll2_owner_t index_list;	/* per-file keyframe index cache */
	lws_sorted_usec_list_t sul_sweep; /* hourly stale-cache sweep */
	lws_dll2_owner_t pss_list; /* active sessions */

	/*
	 * audio shadow transcode thread: browsers cannot play every audio
	 * codec, and transcoding it per-segment restarted the encoder at
	 * every segment boundary, which duplicated a sliver of audio there
	 * each time.  Instead the whole audio stream is transcoded once,
	 * ahead of time, into a "shadow" file under <media-dir>/.atrans, and
	 * segments are cut from that exactly as they are for passthrough
	 * audio.  Same shape as the indexer above: lists under vhd->lock,
	 * atrans_cond signalled with it held.
	 */
	pthread_t atrans_thread;
	pthread_cond_t atrans_cond;
	lws_dll2_owner_t atrans_jobs;	/* pending builds, FIFO */
	struct hls_atrans_job *atrans_running;
	lws_dll2_owner_t atrans_recent;	/* finished builds, see the struct */

	/* WebVTT subtitle cue cache (per media file + track id) */
	lws_dll2_owner_t sub_cache;	/* decoded cue lists, MRU first */
	int sub_cache_count;
	pthread_mutex_t sub_lock;

#if defined(LWS_WITH_STUB)
	struct lws_stub_manager *stub_mgr;
	/* stub process side: the spawn secret we were handed on stdin, which
	 * every request arriving on the UDS must prove knowledge of */
	char stub_secret[129];
#endif
	/*
	 * Who may delete media (see hls_can_delete()): the login state an
	 * lws-login bouncer stamped on the request, read from this wsi when
	 * the bouncer is in-process, or from the request headers when it is
	 * on a box in front of us and the operator set trust-login-headers;
	 * or, with jwt-jwk, the session cookie's grant for service-name
	 */
	int trust_login_headers;
	const char *service_name;
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
	/*
	 * The media file's size and mtime when it was indexed: a cached
	 * index for a replaced file cuts segments from a timeline that no
	 * longer exists (playlists advertising segments past EOF, fragments
	 * that fail to parse), so lookups revalidate against them.
	 */
	int64_t media_size, media_mtime;
	/* some keyframes were found in the bitstream but not flagged by the
	 * container: seeks must not rely on the demuxer's keyframe skipping */
	int unflagged_keyframes;
};

/* Per-segment boundaries, computed from the input video's keyframe index.
 * Defined in hls-av.c, shared with hls-sub.c for subtitle alignment. */
struct hls_segment_info {
	int64_t start_pts;
	int64_t end_pts;
	int64_t seek_pts;
	double duration_sec;
	int seek_any;		/* seek with AVSEEK_FLAG_ANY, see above */
};

/* --- alternate renditions: which streams an A/V body contains --- */

/*
 * The A/V media playlist, init segment and media segment builders take a
 * selector naming what their output carries, so one file can be served as
 * a muxed A/V stream (the original behaviour, used when the container has
 * at most one audio track), or as a video-only variant plus one audio-only
 * rendition per audio track for the client to pick between:
 *
 *   ""    video plus the default audio, muxed
 *   "v"   video only
 *   "aN"  audio only, taken from input stream index N
 *
 * The selector appears as an extra URL path element after the filename
 * (/avstream/<file>/aN, /init/<file>/aN, /segment/<file>/aN/<idx>) and is
 * carried in hls_task.trackid.  Audio-only segments are cut on the same
 * keyframe timeline as the video ones, so segment N of every rendition
 * covers the same span.
 */
enum hls_sel_kind {
	HLS_SEL_MUXED,
	HLS_SEL_VIDEO,
	HLS_SEL_AUDIO,
};

/* Parse a selector; *audio_stream gets N for "aN".  Returns -1 if the
 * string is not one of the forms above (the URL router 404s on that). */
static inline int
hls_parse_sel(const char *sel, enum hls_sel_kind *kind, int *audio_stream)
{
	const char *p;
	int n = 0;

	*audio_stream = -1;
	if (!sel || !*sel) {
		*kind = HLS_SEL_MUXED;
		return 0;
	}
	if (!strcmp(sel, "v")) {
		*kind = HLS_SEL_VIDEO;
		return 0;
	}
	if (*sel != 'a' || !sel[1] || strlen(sel) > 4)
		return -1;
	for (p = sel + 1; *p; p++) {
		if (*p < '0' || *p > '9')
			return -1;
		n = n * 10 + (*p - '0');
	}
	*kind = HLS_SEL_AUDIO;
	*audio_stream = n;

	return 0;
}

/* Description of one audio track in a media file, id "aN" for input
 * stream index N. */
struct hls_audio_track {
	char id[16];
	char lang[16];       /* BCP47-ish: "en", "pt-BR", or "und" */
	char name[64];       /* human-readable, e.g. "English" */
	int  stream_index;   /* AVStream index */
	int  is_default;     /* container's AV_DISPOSITION_DEFAULT */
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

	/*
	 * Rendered VTT segment bodies, indexed by segment number.  Subtitle
	 * segments are latency-critical and tiny, but they were served from
	 * the worker FIFO behind multi-hundred-ms media segment builds: cues
	 * that reach the player's native text track after their start time
	 * has passed are never shown, which dropped runs of subtitles on a
	 * busy box.  The worker renders each segment once and keeps it here
	 * (up to a byte cap); the event loop then serves repeats itself.
	 */
	char **seg_body;
	size_t *seg_body_len;
	int seg_slots;
	size_t seg_bytes_cached;
};

/* per-track cap on cached rendered subtitle segment bodies */
#define HLS_SUBSEG_CACHE_MAX (2 * 1024 * 1024)

struct per_session_data__lws_hls {
	lws_dll2_t pss_list; /* vhd pss_list membership */
	struct lws *wsi;
	uint8_t *segment_buf;
	size_t segment_len;
	size_t segment_pos;

	/* the task we are waiting on, if any (event loop only) */
	struct hls_task *task;
	/* set when the task's result has been moved into segment_buf and the
	 * HTTP response is yet to be started */
	int resp_ready;
	int resp_status;
	const char *resp_content_type;

	/* Thumbnail async state */
	int waiting_for_thumbnail;
	char thumb_filename[256];
	int thumb_t;
	
	int can_delete;		/* this request may delete media */

	/* stub lejp parsing.  The request members are collected and only acted
	 * on once the whole object has parsed, so the secret can be checked
	 * before anything is deleted regardless of member order. */
	struct lejp_ctx jctx;
	int parser_valid;
	char stub_secret[129];
	char stub_delete[256];
	size_t stub_delete_len;	/* sizeof(stub_delete) if it overflowed */
	/* stub side: the reply to the request we just acted on */
	char stub_reply[LWS_PRE + 32];
	size_t stub_reply_len;
#if defined(LWS_WITH_STUB)
	/* http side: our delete request in flight at the stub, and how it
	 * ended (-1: no reply, else the errno the stub's unlink() gave) */
	lws_stub_req_h stub_req;
	int stub_del_result;
	int stub_del_pending;
#endif
};

/* hls-av.c */

/* the vhost's worker thread body */
void *
lws_hls_worker(void *d);

/*
 * Event loop side of the task queue.
 *
 * lws_hls_queue_task() queues work for the session on wsi and leaves the
 * HTTP transaction pending; returns -1 (with a status already sent where
 * possible) if it could not.  lws_hls_collect_done() is called from
 * LWS_CALLBACK_EVENT_WAIT_CANCELLED to hand finished results to their
 * sessions.  lws_hls_task_detach() is called when a session goes away, so
 * its task is dropped or cancelled rather than delivered to freed memory.
 */
int
lws_hls_queue_task(struct lws *wsi, struct per_vhost_data__lws_hls *vhd,
		   enum hls_task_type type, const char *filename,
		   const char *trackid, int segment_idx);

void
lws_hls_collect_done(struct per_vhost_data__lws_hls *vhd);

void
lws_hls_task_detach(struct per_vhost_data__lws_hls *vhd,
		    struct per_session_data__lws_hls *pss);

void
lws_hls_task_free(struct hls_task *t);

int
lws_hls_serve_thumbnail(struct lws *wsi, const char *media_dir,
			const char *filename, int t);

int
lws_hls_serve_dir(struct lws *wsi, struct per_vhost_data__lws_hls *vhd);

/*
 * Remove subdirectories of media-dir that no longer hold anything the
 * user could play anywhere beneath them, contents and all: media dirs
 * outlive their last file for no reason, whether it went through our
 * delete or outside us.  The toplevel media dir itself is never touched,
 * and dot-dirs (the .index / .atrans caches) are not playable but also
 * not purged from the toplevel.  Runs at init and on the hourly sweep.
 */
void
lws_hls_purge_empty_dirs(struct per_vhost_data__lws_hls *vhd);

/*
 * The same, for the one toplevel subdirectory [top, top + len) of media-dir,
 * after media was deleted from somewhere below it
 */
void
lws_hls_purge_subdir(struct per_vhost_data__lws_hls *vhd, const char *top,
		     size_t len);

/*
 * Body builders, run on the worker thread.  They never touch a wsi; they
 * fill r->status, and for HTTP_STATUS_OK, r->body / r->len / r->content_type.
 * cancel may be NULL.
 */
/*
 * sel is the rendition selector described above ("" / "v" / "aN"); an
 * "aN" naming a stream that is not an audio stream gives 404.
 */
void
lws_hls_build_init(struct per_vhost_data__lws_hls *vhd, const char *media_dir,
		   const char *filename, const char *sel, volatile int *cancel,
		   struct hls_result *r);

/* A/V media playlist (referenced as a variant from the master playlist
 * when subtitles or alternate audio exist, or served directly otherwise). */
void
lws_hls_build_manifest(struct per_vhost_data__lws_hls *vhd,
		       const char *media_dir, const char *filename,
		       const char *sel, volatile int *cancel,
		       struct hls_result *r);

void
lws_hls_build_segment(struct per_vhost_data__lws_hls *vhd,
		      const char *media_dir, const char *filename,
		      const char *sel, int segment_idx, volatile int *cancel,
		      struct hls_result *r);

/* List the audio streams of a media file, in stream index order.  Returns
 * a malloc'd array and count in *out_count; caller free()s it.  NULL / 0
 * if none. */
struct hls_audio_track *
lws_hls_discover_audio(const char *media_dir, const char *filename,
		       int *out_count);

/* Compute segment [start_pts, end_pts] / duration for the target segment
 * index of a media file, plus the total segment count. Used by both the
 * A/V and subtitle playlist generators to keep a shared timeline.  May scan
 * the whole file (twice) to build the index the first time a file is seen,
 * so worker thread only. */
int
lws_hls_get_segment_info(struct per_vhost_data__lws_hls *vhd, const char *filename,
			 AVFormatContext *in_ctx, int video_idx, int target_seg_idx,
			 struct hls_segment_info *out_info, int *out_total_segments,
			 volatile int *cancel);

/* hls-media.c: is a media file all there?  See the file comment */

/*
 * How long after its last write a media file is taken to still be arriving.
 * A copy in progress writes continuously; this only has to ride out the
 * pauses of a slow network copy.
 */
#define HLS_MEDIA_SETTLE_SECS	30

enum hls_media_state {
	HLS_MEDIA_COMPLETE,	/* serve it */
	HLS_MEDIA_ARRIVING,	/* written to within HLS_MEDIA_SETTLE_SECS */
	HLS_MEDIA_TRUNCATED,	/* shorter than its container says it is */
	HLS_MEDIA_GONE,		/* not there, or not a regular file */
};

/*
 * The state of media-dir/filename; if st_out is given it gets the file's
 * stat when it is there, so a caller can later tell whether it changed.
 * Nothing libavformat opens should be built, cached or persisted from a
 * file this does not call complete.
 */
enum hls_media_state
lws_hls_media_state(const char *media_dir, const char *filename,
		    struct stat *st_out);

/* written to recently enough to be a copy in progress? */
int
lws_hls_media_settling(const struct stat *st);

/* "complete", "arriving", "incomplete" or "gone", for logs and JSON */
const char *
lws_hls_media_state_name(enum hls_media_state ms);

/*
 * Does this (base)name say playable media: .mp4 / .mkv, any case, and not
 * a dotfile (which is also how copies in progress are often named)?
 */
int
lws_hls_is_media_name(const char *name);

/* hls-index.c: the on-disk copy of vhd->index_list, see the file comment */

/* cap on keyframes indexed per file, from the scan and from disk */
#define HLS_SCAN_MAX_KF 200000

/* persist a freshly built index; failure is logged and non-fatal */
int
lws_hls_index_save(struct per_vhost_data__lws_hls *vhd,
		   const struct hls_file_index *idx);

/* malloc'd index for (filename, video_idx) from disk if one exists and
 * still matches the media file's size and mtime, else NULL; caller owns
 * it (adds it to vhd->index_list) */
struct hls_file_index *
lws_hls_index_load(struct per_vhost_data__lws_hls *vhd, const char *filename,
		   int video_idx);

/* the media file is going: drop its index from memory and disk */
void
lws_hls_index_forget(struct per_vhost_data__lws_hls *vhd, const char *filename);

/* disk part of the above only, for the stub child which has no cache */
void
lws_hls_index_unlink(const char *media_dir, const char *filename);

/*
 * Worker only, from lws_hls_get_segment_info() when neither memory nor disk
 * has the index: hand the build to the indexer thread and park the current
 * task behind it.  Returns 1 if that was done (the caller returns -1 and
 * unwinds; the worker requeues the task when the index exists), 0 if the
 * caller should build inline after all (a recent build of this file failed).
 */
int
lws_hls_index_defer(struct per_vhost_data__lws_hls *vhd, const char *filename,
		    volatile int *cancel);

/* worker: what to do with a task whose builder returned with t->parked set */
void
lws_hls_task_park(struct per_vhost_data__lws_hls *vhd, struct hls_task *t);

/* vhd->lock held: is this recorded shadow wait already satisfied?  See
 * lws_hls_task_park() for why parking re-checks */
int
lws_hls_atrans_wait_done(struct per_vhost_data__lws_hls *vhd,
			 const char *filename, int audio_idx, int64_t need_us);

/* the indexer thread; started and joined beside the worker */
void *
lws_hls_indexer(void *d);

/* after the join: free jobs, results and parked tasks */
void
lws_hls_indexer_destroy(struct per_vhost_data__lws_hls *vhd);

/* progress pointer for scan_keyframes(), if this is the indexer thread */
volatile int *
lws_hls_index_progress(struct per_vhost_data__lws_hls *vhd);

/*
 * Event loop: JSON for /index/<file>, queueing the build if there is none.
 * can_delete is the request's delete decision (hls_can_delete()), so the
 * player page shows its delete button from the server's own answer.
 */
int
lws_hls_index_status(struct per_vhost_data__lws_hls *vhd, const char *filename,
		     char *json, size_t len, int can_delete);

/* remove indexes whose media is gone or changed: once at init, then hourly */
void
lws_hls_index_sweep_start(struct per_vhost_data__lws_hls *vhd);
void
lws_hls_index_sweep_stop(struct per_vhost_data__lws_hls *vhd);

/* hls-atrans.c: the pre-transcoded audio shadow cache, see the file comment */

/*
 * Decoder + AAC encoder + resampler + sample fifo for one audio stream
 * (defined here: both hls-av.c and hls-atrans.c drive one).
 */
struct hls_audio_transcoder {
	AVCodecContext *dec_ctx;
	AVCodecContext *enc_ctx;
	SwrContext *swr_ctx;
	AVAudioFifo *fifo;
	int64_t next_pts;
};

enum hls_atrans_state {
	HLS_ATRANS_NONE,	/* no shadow: a build has been queued */
	HLS_ATRANS_RUNNING,	/* build in progress, *covered_us so far */
	HLS_ATRANS_READY,	/* complete shadow on disk */
	HLS_ATRANS_FAILED,	/* tried recently and failed: use the inline path */
};

/*
 * Worker: is there a usable shadow for (filename, audio_idx)?  Asking is
 * what queues the build.  *covered_us gets the covered timeline (us from
 * the media start; INT64_MAX when complete) for RUNNING, untouched
 * otherwise.
 */
enum hls_atrans_state
lws_hls_atrans_lookup(struct per_vhost_data__lws_hls *vhd, const char *filename,
		      int audio_idx, int64_t *covered_us);

/* the shadow media path for (filename, audio_idx), for the worker to open */
void
lws_hls_atrans_path(struct per_vhost_data__lws_hls *vhd, const char *filename,
		     int audio_idx, char *buf, size_t len);

/*
 * Worker, from the segment builder when the shadow does not cover what the
 * segment needs: park vhd->running until it does.  Returns 1 if the task
 * was parked (the caller unwinds as if cancelled, like the index defer),
 * 0 if it should not wait behind this build (it failed recently).
 */
int
lws_hls_atrans_defer(struct per_vhost_data__lws_hls *vhd, const char *filename,
		     int audio_idx, int64_t need_us, volatile int *cancel);

/* the atrans thread; started and joined beside the worker and indexer */
void *
lws_hls_atrans_thread(void *d);

/* after the join: free jobs and recent results */
void
lws_hls_atrans_destroy(struct per_vhost_data__lws_hls *vhd);

/* the media file is going: drop its shadow jobs, and its shadow files */
void
lws_hls_atrans_forget(struct per_vhost_data__lws_hls *vhd, const char *filename);
void
lws_hls_atrans_unlink(const char *media_dir, const char *filename);

/* remove shadows whose media is gone or changed, and enforce the size cap:
 * called beside the index sweep */
void
lws_hls_atrans_sweep(struct per_vhost_data__lws_hls *vhd);

/* event loop: the atrans fields for the /index/<file> status JSON */
int
lws_hls_atrans_status_json(struct per_vhost_data__lws_hls *vhd,
			   const char *filename, char *buf, size_t len);

/*
 * hls-av.c: the audio transcoder the shadow builder and the (fallback)
 * per-segment path share.  Creates decoder + AAC encoder + resampler +
 * sample fifo for input stream audio_idx of in_ctx.
 */
struct hls_audio_transcoder *
lws_hls_audio_tx_create(AVFormatContext *in_ctx, int audio_idx);
void
lws_hls_audio_tx_free(struct hls_audio_transcoder *tx);

/* does this codec need transcoding for browser playback? */
int
lws_hls_needs_audio_transcode(enum AVCodecID codec_id);

/*
 * Feed one input packet; encoded AAC packets (in the out stream's
 * timebase, starting from the input packet's pts) go to out_ctx.  The
 * tracking out-params may be NULL when the caller has no use for them.
 * Returns 0, or -1 if the muxer refused an encoded packet.
 */
int
lws_hls_audio_tx_packet(AVFormatContext *in_ctx, AVFormatContext *out_ctx,
			struct hls_audio_transcoder *tx, AVPacket *pkt,
			int out_stream_idx, int64_t shift_offset_out_audio,
			int64_t *first_audio_pts, int64_t *first_audio_dts,
			int64_t *last_audio_pts, int64_t *last_audio_dts,
			int *audio_packets_written, int64_t *last_dts,
			int segment_idx);

/* drain decoder, encoder and fifo (padding the last frame with silence) */
void
lws_hls_audio_tx_flush(AVFormatContext *out_ctx,
		       struct hls_audio_transcoder *tx, int out_stream_idx,
		       int64_t *first_audio_pts, int64_t *first_audio_dts,
		       int64_t *last_audio_pts, int64_t *last_audio_dts,
		       int *audio_packets_written, int64_t *last_dts,
		       int segment_idx);

/* hls-sub.c */

/*
 * Event loop: the rendered body of subtitle segment seg_idx of
 * (filename, trackid) if the worker cached it from an earlier render.
 * Returns a malloc'd buffer with the payload at +LWS_PRE the caller
 * owns (NULL on miss).
 */
char *
lws_hls_sub_segment_cached(struct per_vhost_data__lws_hls *vhd,
			   const char *filename, const char *trackid,
			   int seg_idx, size_t *len);

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

/*
 * Body builders, worker thread only, same contract as the hls-av.c ones.
 */

/* Master playlist dispatcher: if the file has subtitle tracks or more than
 * one audio track, emit a master playlist (one #EXT-X-STREAM-INF, per-track
 * #EXT-X-MEDIA TYPE=SUBTITLES, and with several audio tracks a video-only
 * variant plus per-track #EXT-X-MEDIA TYPE=AUDIO renditions); otherwise
 * delegate to the plain muxed A/V media playlist. */
void
lws_hls_build_stream(struct per_vhost_data__lws_hls *vhd, const char *media_dir,
		     const char *filename, volatile int *cancel,
		     struct hls_result *r);

/* Subtitle media playlist for one track. */
void
lws_hls_build_sub_playlist(struct per_vhost_data__lws_hls *vhd,
			   const char *media_dir, const char *filename,
			   const char *trackid, volatile int *cancel,
			   struct hls_result *r);

/* One WebVTT segment: cues whose window overlaps [seg_start, seg_end),
 * rebased to segment-relative timestamps. */
void
lws_hls_build_sub_segment(struct per_vhost_data__lws_hls *vhd,
			  const char *media_dir, const char *filename,
			  const char *trackid, int seg_idx, volatile int *cancel,
			  struct hls_result *r);
#endif /* PRIVATE_LWS_HLS_H */
