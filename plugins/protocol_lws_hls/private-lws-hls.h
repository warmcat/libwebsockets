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
	
	struct thumb_cache *cache_head;
	int cache_count;
	
	struct hls_file_index *index_head;
	struct per_session_data__lws_hls *pss_list; /* active sessions */
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

struct per_session_data__lws_hls {
	struct per_session_data__lws_hls *pss_list;
	struct lws *wsi;
	uint8_t *segment_buf;
	size_t segment_len;
	size_t segment_pos;
	
	/* Thumbnail async state */
	int waiting_for_thumbnail;
	char thumb_filename[256];
};

/* hls-av.c */
void *
lws_hls_thumbnail_worker(void *d);

int
lws_hls_serve_thumbnail(struct lws *wsi, const char *media_dir, const char *filename);
int
lws_hls_serve_dir(struct lws *wsi, const char *media_dir);

/* hls-av.c */
int
lws_hls_serve_thumbnail(struct lws *wsi, const char *media_dir, const char *filename);

int
lws_hls_serve_init(struct lws *wsi, const char *media_dir, const char *filename);

int
lws_hls_serve_manifest(struct lws *wsi, const char *media_dir, const char *filename);

int
lws_hls_serve_segment(struct lws *wsi, const char *media_dir, const char *filename, int segment_idx);
