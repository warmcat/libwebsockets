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
 * Is a media file all there?
 *
 * Media gets into media-dir by being copied there, which for a film over a
 * network is minutes, and the listing sees it the whole time.  libavformat
 * opens a partial file happily and describes a shorter film, and what we
 * build from that - the keyframe index, the audio shadows, thumbnails - is
 * persisted or cached as if it were the whole thing.
 *
 * Two independent tests, either of which says "not yet":
 *
 *  - the container's own framing.  Matroska / webm declare the size of the
 *    Segment up front; an mp4 is a run of top-level boxes, each declaring its
 *    size, and it needs a moov, which is written last unless the file was
 *    made "faststart".  A file shorter than its container says, or an mp4
 *    without a moov, is incomplete however old it is: a copy that stalled or
 *    was interrupted.  (A matroska written live, eg by a recorder, may
 *    declare an unknown size, and that says nothing either way.)
 *
 *  - it was written to in the last HLS_MEDIA_SETTLE_SECS: a copy still in
 *    progress, whatever the container.
 *
 * Only a few small reads at the start of the file for matroska, one per
 * top-level box for mp4, so this is cheap enough for the event loop.
 */

#include "private-lws-hls.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <strings.h>

/* bounds the walk of a fragmented mp4, which is a pair of boxes a fragment */
#define HLS_MP4_MAX_BOXES	(256 * 1024)

/* what the framing says */
enum hls_framing {
	HLS_FRAMING_OK,		/* all there, or nothing to say */
	HLS_FRAMING_SHORT,	/* the file ends before its container does */
};

static int
hls_media_pread(int fd, void *buf, size_t len, int64_t pos)
{
	return pread(fd, buf, len, (off_t)pos) == (ssize_t)len ? 0 : -1;
}

int
lws_hls_is_media_name(const char *name)
{
	static const char * const exts[] = { ".mp4", ".mkv" };
	const char *base = strrchr(name, '/');
	size_t nl, i;

	base = base ? base + 1 : name;
	/*
	 * Dotfiles are never media: that is also how rsync and friends name
	 * the temporary file a copy goes into, eg .Film.mkv.Xq3v9A
	 */
	if (base[0] == '.')
		return 0;

	nl = strlen(base);
	for (i = 0; i < LWS_ARRAY_SIZE(exts); i++)
		if (nl > 4 && !strcasecmp(base + nl - 4, exts[i]))
			return 1;

	return 0;
}

/*
 * One EBML variable-length integer at pos: an element ID (marker bit kept,
 * as IDs are written) or an element size (marker bit masked off).  Returns
 * its length in bytes, 0 if it is not a valid vint, or -1 if the file ends
 * inside it.  *unknown is set for a size of all ones, "unknown size".
 */
static int
hls_ebml_vint(int fd, int64_t pos, int64_t fsize, int is_size, uint64_t *v,
	      int *unknown)
{
	uint8_t b[8];
	int len = 1, i;

	if (pos >= fsize || hls_media_pread(fd, b, 1, pos))
		return -1;

	while (len <= 8 && !(b[0] & (0x80 >> (len - 1))))
		len++;
	if (len > 8)
		return 0;
	if (pos + len > fsize || hls_media_pread(fd, b, (size_t)len, pos))
		return -1;

	*v = is_size ? (b[0] & (0xffu >> len)) : b[0];
	for (i = 1; i < len; i++)
		*v = (*v << 8) | b[i];

	if (unknown)
		*unknown = is_size && *v == (1ull << (7 * len)) - 1;

	return len;
}

/* one element header at *pos: *pos is left at its payload */
static int
hls_ebml_elem(int fd, int64_t *pos, int64_t fsize, uint64_t *id,
	      uint64_t *size, int *unknown)
{
	int n = hls_ebml_vint(fd, *pos, fsize, 0, id, NULL);

	if (n <= 0)
		return n;
	*pos += n;
	n = hls_ebml_vint(fd, *pos, fsize, 1, size, unknown);
	if (n <= 0)
		return n;
	*pos += n;

	return 1;
}

static enum hls_framing
hls_framing_mkv(int fd, int64_t fsize)
{
	int64_t pos = 0;
	uint64_t id, size;
	int unknown, n;

	/* the EBML header... */
	n = hls_ebml_elem(fd, &pos, fsize, &id, &size, &unknown);
	if (n < 0)
		return HLS_FRAMING_SHORT;
	if (!n || id != 0x1A45DFA3 || unknown)
		return HLS_FRAMING_OK; /* not matroska: not ours to judge */
	if (size > (uint64_t)(fsize - pos))
		return HLS_FRAMING_SHORT;
	pos += (int64_t)size;

	/* ...then the Segment, holding everything else */
	n = hls_ebml_elem(fd, &pos, fsize, &id, &size, &unknown);
	if (n < 0)
		return HLS_FRAMING_SHORT;
	if (!n || id != 0x18538067 || unknown)
		return HLS_FRAMING_OK;

	return size > (uint64_t)(fsize - pos) ? HLS_FRAMING_SHORT :
						HLS_FRAMING_OK;
}

static enum hls_framing
hls_framing_mp4(int fd, int64_t fsize)
{
	int64_t pos = 0;
	int moov = 0, boxes = 0, i;

	while (pos < fsize) {
		uint8_t h[16];
		uint64_t size;
		int hl = 8;

		if (++boxes > HLS_MP4_MAX_BOXES)
			return HLS_FRAMING_OK;

		if (fsize - pos < 8 || hls_media_pread(fd, h, 8, pos))
			return HLS_FRAMING_SHORT;

		/*
		 * A box type that is not a fourcc: all zeros is a hole a
		 * copier preallocated and has not reached yet, anything else
		 * is not an mp4 we can judge
		 */
		for (i = 4; i < 8; i++)
			if (!isprint(h[i]))
				break;
		if (i != 8)
			return !h[4] && !h[5] && !h[6] && !h[7] ?
					HLS_FRAMING_SHORT : HLS_FRAMING_OK;

		size = ((uint64_t)h[0] << 24) | ((uint64_t)h[1] << 16) |
		       ((uint64_t)h[2] << 8) | h[3];
		if (size == 1) {
			/* 64-bit size follows the type */
			if (fsize - pos < 16 ||
			    hls_media_pread(fd, h + 8, 8, pos + 8))
				return HLS_FRAMING_SHORT;
			size = 0;
			for (i = 8; i < 16; i++)
				size = (size << 8) | h[i];
			hl = 16;
		} else if (!size)
			/* the last box, running to the end of the file */
			size = (uint64_t)(fsize - pos);

		if (size < (uint64_t)hl)
			return HLS_FRAMING_OK; /* malformed: not ours to judge */

		if (!memcmp(h + 4, "moov", 4))
			moov = 1;

		if (size > (uint64_t)(fsize - pos))
			return HLS_FRAMING_SHORT;
		pos += (int64_t)size;
	}

	return moov ? HLS_FRAMING_OK : HLS_FRAMING_SHORT;
}

enum hls_media_state
lws_hls_media_state(const char *media_dir, const char *filename,
		    struct stat *st_out)
{
	enum hls_framing fr = HLS_FRAMING_OK;
	char path[1024];
	struct stat st;
	size_t nl;
	int fd;

	lws_snprintf(path, sizeof(path), "%s/%s", media_dir, filename);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return HLS_MEDIA_GONE;
	if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
		close(fd);
		return HLS_MEDIA_GONE;
	}
	if (st_out)
		*st_out = st;

	nl = strlen(filename);
	if (nl > 4 && !strcasecmp(filename + nl - 4, ".mkv"))
		fr = hls_framing_mkv(fd, (int64_t)st.st_size);
	else if (nl > 4 && !strcasecmp(filename + nl - 4, ".mp4"))
		fr = hls_framing_mp4(fd, (int64_t)st.st_size);
	close(fd);

	/*
	 * A copy in progress is usually short too: it is only incomplete,
	 * rather than still arriving, once nothing has written to it for a
	 * while.  And a file whose framing looks whole but is still being
	 * written (a copier that preallocates the whole size, then fills it
	 * in) is not complete either.
	 */
	if (lws_hls_media_settling(&st))
		return HLS_MEDIA_ARRIVING;

	return fr == HLS_FRAMING_SHORT ? HLS_MEDIA_TRUNCATED :
					 HLS_MEDIA_COMPLETE;
}

int
lws_hls_media_settling(const struct stat *st)
{
	time_t now = time(NULL);

	/*
	 * Either side of now: a copy from a box whose clock is a little
	 * ahead is still a copy in progress, while a file whose original
	 * mtime was preserved, however odd, is not being written
	 */
	return st->st_mtime > now - HLS_MEDIA_SETTLE_SECS &&
	       st->st_mtime < now + HLS_MEDIA_SETTLE_SECS;
}

const char *
lws_hls_media_state_name(enum hls_media_state ms)
{
	switch (ms) {
	case HLS_MEDIA_COMPLETE:
		return "complete";
	case HLS_MEDIA_ARRIVING:
		return "arriving";
	case HLS_MEDIA_TRUNCATED:
		return "incomplete";
	default:
		break;
	}

	return "gone";
}
