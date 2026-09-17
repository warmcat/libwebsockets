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
 *
 * Persistent keyframe index cache.
 *
 * Building a file's keyframe index means reading the whole file, which for
 * a large MKV is minutes; keeping the result only in memory meant paying
 * that again after every restart.  Each index is written under
 * <media-dir>/.index/<sha1 of the media filename>.idx once built, and loaded
 * from there on the next miss.  The hashed name means nothing in there can
 * be mistaken for media (the directory listing skips dot-dirs anyway), and
 * the header records which media file, at what size and mtime, it belongs
 * to, so a stale or orphaned index is recognised and removed: when the
 * media is deleted through us, at protocol init, and on an hourly sweep.
 */

#include "private-lws-hls.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define HLS_INDEX_SUBDIR	".index"
#define HLS_INDEX_MAGIC		"LWSHLSIX"
#define HLS_INDEX_VERSION	1
#define HLS_INDEX_SWEEP_US	(3600 * LWS_US_PER_SEC)

struct hls_index_hdr {
	char		magic[8];
	uint32_t	version;
	uint32_t	video_idx;
	uint32_t	count;
	uint32_t	unflagged_keyframes;
	int64_t		size;	/* of the media file when it was indexed */
	int64_t		mtime;
	char		filename[256];
};

/* followed by hdr.count of these */
struct hls_index_disk_entry {
	int64_t		pos;
	int64_t		timestamp;
	int64_t		dts;
	int32_t		min_distance;
	int32_t		size;
	int32_t		flags;
	int32_t		pad;
};

static void
hls_index_dir(const char *media_dir, char *buf, size_t len)
{
	lws_snprintf(buf, len, "%s/" HLS_INDEX_SUBDIR, media_dir);
}

static void
hls_index_path(const char *media_dir, const char *filename, char *buf,
	       size_t len)
{
	unsigned char digest[20];
	char hex[41];

	lws_SHA1((const unsigned char *)filename, strlen(filename), digest);
	lws_hex_from_byte_array(digest, sizeof(digest), hex, sizeof(hex));
	lws_snprintf(buf, len, "%s/" HLS_INDEX_SUBDIR "/%s.idx", media_dir, hex);
}

static int
hls_media_stat(const char *media_dir, const char *filename, int64_t *size,
	       int64_t *mtime)
{
	char path[1024];
	struct stat st;

	lws_snprintf(path, sizeof(path), "%s/%s", media_dir, filename);
	if (stat(path, &st))
		return -1;

	*size = (int64_t)st.st_size;
	*mtime = (int64_t)st.st_mtime;

	return 0;
}

/*
 * Read and validate just the header of an index file: it must be ours, and
 * the media file it names must still exist at the recorded size and mtime.
 * Returns 0 if so, 1 if the file is stale or orphaned (caller removes it),
 * -1 if it could not be read.
 */
static int
hls_index_read_hdr(const char *media_dir, const char *path,
		   struct hls_index_hdr *hdr)
{
	int64_t size, mtime;
	int fd, n;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = (int)read(fd, hdr, sizeof(*hdr));
	close(fd);

	if (n != (int)sizeof(*hdr) ||
	    memcmp(hdr->magic, HLS_INDEX_MAGIC, sizeof(hdr->magic)) ||
	    hdr->version != HLS_INDEX_VERSION ||
	    !memchr(hdr->filename, '\0', sizeof(hdr->filename)) ||
	    !hdr->filename[0] || strchr(hdr->filename, '/'))
		return 1;

	if (hls_media_stat(media_dir, hdr->filename, &size, &mtime) ||
	    size != hdr->size || mtime != hdr->mtime)
		return 1;

	return 0;
}

int
lws_hls_index_save(struct per_vhost_data__lws_hls *vhd,
		   const struct hls_file_index *idx)
{
	struct hls_index_hdr hdr;
	struct hls_index_disk_entry de;
	char dir[1024], path[1024], tmp[1100];
	int fd, i;

	memset(&hdr, 0, sizeof(hdr));
	memcpy(hdr.magic, HLS_INDEX_MAGIC, sizeof(hdr.magic));
	hdr.version = HLS_INDEX_VERSION;
	hdr.video_idx = (uint32_t)idx->video_idx;
	hdr.count = (uint32_t)idx->count;
	hdr.unflagged_keyframes = (uint32_t)idx->unflagged_keyframes;
	lws_strncpy(hdr.filename, idx->filename, sizeof(hdr.filename));

	if (hls_media_stat(vhd->media_dir, idx->filename, &hdr.size,
			   &hdr.mtime))
		return -1;

	hls_index_dir(vhd->media_dir, dir, sizeof(dir));
	if (mkdir(dir, 0700) && errno != EEXIST) {
		lwsl_warn("%s: cannot create %s: %s (index not persisted)\n",
			  __func__, dir, strerror(errno));
		return -1;
	}

	hls_index_path(vhd->media_dir, idx->filename, path, sizeof(path));
	/* write it beside its final name, and rename into place when
	 * complete, so a reader never sees a partial index */
	lws_snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		lwsl_warn("%s: cannot create %s: %s (index not persisted)\n",
			  __func__, tmp, strerror(errno));
		return -1;
	}

	if (write(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
		goto fail;

	for (i = 0; i < idx->count; i++) {
		memset(&de, 0, sizeof(de));
		de.pos		= idx->entries[i].pos;
		de.timestamp	= idx->entries[i].timestamp;
		de.dts		= idx->entries[i].dts;
		de.min_distance	= idx->entries[i].min_distance;
		de.size		= idx->entries[i].size;
		de.flags	= idx->entries[i].flags;
		if (write(fd, &de, sizeof(de)) != (ssize_t)sizeof(de))
			goto fail;
	}

	close(fd);
	if (rename(tmp, path)) {
		unlink(tmp);
		return -1;
	}

	lwsl_notice("HLS-INDEX: %s: %d keyframes persisted to %s\n",
		    idx->filename, idx->count, path);

	return 0;

fail:
	lwsl_warn("%s: write %s failed: %s\n", __func__, tmp, strerror(errno));
	close(fd);
	unlink(tmp);

	return -1;
}

struct hls_file_index *
lws_hls_index_load(struct per_vhost_data__lws_hls *vhd, const char *filename,
		   int video_idx)
{
	struct hls_file_index *idx = NULL;
	struct hls_index_disk_entry de;
	struct hls_index_hdr hdr;
	char path[1024];
	int fd = -1, n;
	uint32_t i;

	hls_index_path(vhd->media_dir, filename, path, sizeof(path));

	n = hls_index_read_hdr(vhd->media_dir, path, &hdr);
	if (n < 0)
		return NULL;
	if (n > 0 || strcmp(hdr.filename, filename) ||
	    hdr.video_idx != (uint32_t)video_idx ||
	    hdr.count > HLS_SCAN_MAX_KF) {
		lwsl_notice("HLS-INDEX: %s: dropping stale index %s\n",
			    filename, path);
		unlink(path);
		return NULL;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;
	if (lseek(fd, (off_t)sizeof(hdr), SEEK_SET) != (off_t)sizeof(hdr))
		goto bail;

	idx = calloc(1, sizeof(*idx));
	if (!idx)
		goto bail;
	idx->entries = malloc(hdr.count * sizeof(*idx->entries));
	if (!idx->entries)
		goto bail;

	for (i = 0; i < hdr.count; i++) {
		if (read(fd, &de, sizeof(de)) != (ssize_t)sizeof(de)) {
			lwsl_notice("HLS-INDEX: %s: dropping short index %s\n",
				    filename, path);
			unlink(path);
			goto bail;
		}
		idx->entries[i].pos		= de.pos;
		idx->entries[i].timestamp	= de.timestamp;
		idx->entries[i].dts		= de.dts;
		idx->entries[i].min_distance	= de.min_distance;
		idx->entries[i].size		= de.size;
		idx->entries[i].flags		= de.flags;
	}
	close(fd);

	lws_strncpy(idx->filename, filename, sizeof(idx->filename));
	idx->video_idx = video_idx;
	idx->count = (int)hdr.count;
	idx->unflagged_keyframes = !!hdr.unflagged_keyframes;

	lwsl_notice("HLS-INDEX: %s: %d keyframes loaded from %s\n", filename,
		    idx->count, path);

	return idx;

bail:
	if (fd >= 0)
		close(fd);
	if (idx) {
		free(idx->entries);
		free(idx);
	}

	return NULL;
}

void
lws_hls_index_unlink(const char *media_dir, const char *filename)
{
	char path[1024];

	hls_index_path(media_dir, filename, path, sizeof(path));
	if (!unlink(path))
		lwsl_notice("HLS-INDEX: %s: removed %s\n", filename, path);
}

void
lws_hls_index_forget(struct per_vhost_data__lws_hls *vhd, const char *filename)
{
	pthread_mutex_lock(&vhd->lock);
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->index_list)) {
		struct hls_file_index *idx = lws_container_of(d,
					struct hls_file_index, list);

		if (!strcmp(idx->filename, filename)) {
			lws_dll2_remove(&idx->list);
			free(idx->entries);
			free(idx);
		}
	} lws_end_foreach_dll_safe(d, d1);
	pthread_mutex_unlock(&vhd->lock);

	lws_hls_index_unlink(vhd->media_dir, filename);
}

/*
 * Sweep: drop every index file whose media is gone or changed, and every
 * in-memory index likewise.  Only headers are read, so this is cheap enough
 * for the event loop.
 */

static int
hls_index_sweep_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct per_vhost_data__lws_hls *vhd =
			(struct per_vhost_data__lws_hls *)user;
	struct hls_index_hdr hdr;
	char path[1024];
	size_t nl;

	if (lde->type != LDOT_FILE)
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
	nl = strlen(lde->name);

	/* a .tmp is a save that never completed: nothing will finish it */
	if (nl > 4 && !strcmp(lde->name + nl - 4, ".tmp")) {
		unlink(path);
		return 0;
	}

	if (nl < 4 || strcmp(lde->name + nl - 4, ".idx"))
		return 0;

	memset(&hdr, 0, sizeof(hdr));
	if (hls_index_read_hdr(vhd->media_dir, path, &hdr) == 0)
		return 0;
	hdr.filename[sizeof(hdr.filename) - 1] = '\0';

	lwsl_notice("HLS-INDEX: sweep: removing %s (%s)\n", path,
		    hdr.filename[0] ? hdr.filename : "unreadable");
	unlink(path);

	return 0;
}

void
lws_hls_index_sweep(struct per_vhost_data__lws_hls *vhd)
{
	char dir[1024];

	pthread_mutex_lock(&vhd->lock);
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->index_list)) {
		struct hls_file_index *idx = lws_container_of(d,
					struct hls_file_index, list);
		int64_t size, mtime;

		if (!hls_media_stat(vhd->media_dir, idx->filename, &size,
				    &mtime))
			continue;

		lwsl_notice("HLS-INDEX: sweep: %s is gone, dropping index\n",
			    idx->filename);
		lws_dll2_remove(&idx->list);
		free(idx->entries);
		free(idx);
	} lws_end_foreach_dll_safe(d, d1);
	pthread_mutex_unlock(&vhd->lock);

	hls_index_dir(vhd->media_dir, dir, sizeof(dir));
	/* no dir yet is the usual case: nothing has been indexed */
	if (access(dir, F_OK))
		return;

	lws_dir(dir, vhd, hls_index_sweep_cb);
}

static void
hls_index_sweep_sul(lws_sorted_usec_list_t *sul)
{
	struct per_vhost_data__lws_hls *vhd = lws_container_of(sul,
				struct per_vhost_data__lws_hls, sul_sweep);

	lws_hls_index_sweep(vhd);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_sweep, hls_index_sweep_sul,
			 HLS_INDEX_SWEEP_US);
}

void
lws_hls_index_sweep_start(struct per_vhost_data__lws_hls *vhd)
{
	lws_hls_index_sweep(vhd);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_sweep, hls_index_sweep_sul,
			 HLS_INDEX_SWEEP_US);
}

void
lws_hls_index_sweep_stop(struct per_vhost_data__lws_hls *vhd)
{
	lws_sul_cancel(&vhd->sul_sweep);
}
