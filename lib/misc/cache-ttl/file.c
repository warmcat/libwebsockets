/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Implements a cache backing store compatible with netscape cookies.txt format
 * There is one entry per "line", and fields are tab-delimited
 *
 * We need to know the format here, because while the unique cookie tag consists
 * of "hostname|urlpath|cookiename", that does not appear like that in the file;
 * we have to go parse the fields and synthesize the corresponding tag.
 *
 * We rely on all the fields except the cookie value fitting in a 256 byte
 * buffer, and allow eating multiple buffers to get a huge cookie values.
 *
 * Because the cookie file is a device-wide asset, although lws will change it
 * from the lws thread without conflict, there may be other processes that will
 * change it by removal and regenerating the file asynchronously.  For that
 * reason, file handles are opened fresh each time we want to use the file, so
 * we always get the latest version.
 *
 * When updating the file ourselves, we use a lockfile to ensure our process
 * has exclusive access.
 *
 *
 * Tag Matching rules
 *
 * There are three kinds of tag matching rules
 *
 * 1) specific - tag strigs must be the same
 * 2) wilcard - tags matched using optional wildcards
 * 3) wildcard + lookup - wildcard, but path part matches using cookie scope rules
 *
 * Only lookups use wildcards.  Writes, gets and removes name one specific
 * item and match it literally: the fields of the key are chosen by whoever
 * set the cookie, and a '*' in them must not turn a remove into a mass
 * delete.  Writes refuse lines whose tag fields could not be told apart from
 * a wildcard or a separator.
 */

#include <private-lib-core.h>
#include "private-lib-misc-cache-ttl.h"

#include <sys/stat.h>

typedef enum nsc_iterator_ret {
	NIR_CONTINUE		= 0,
	NIR_FINISH_OK		= 1,
	NIR_FINISH_ERROR	= -1
} nsc_iterator_ret_t;

typedef enum cbreason {
	LCN_SOL			= (1 << 0),
	LCN_EOL			= (1 << 1)
} cbreason_t;

typedef int (*nsc_cb_t)(lws_cache_nscookiejar_t *cache, void *opaque, int flags,
			const char *buf, size_t size);

/*
 * The iterator's line buffer.  The chunk flagged LCN_SOL holds the whole line
 * if it fits, else the first NSC_SOL_MAX bytes of it, so the columns making
 * up the tag must fit in that for us to be able to index the line.
 */
#define NSC_LINE_BUF		256
#define NSC_SOL_MAX		(NSC_LINE_BUF - 1)
#define NSC_TAG_MAX		NSC_LINE_BUF

/* 9999-12-31 23:59:59 UTC, the latest the cookie date parser produces */
#define NSC_EXPIRY_MAX_SECS	253402300799ull

enum {
	NSC_LTT_OK,
	NSC_LTT_MALFORMED,	/* not a jar line we understand */
	NSC_LTT_TOO_LONG,	/* well-formed, but we cannot index it */
};

/*
 * Every write or remove rewrites the whole jar, and lookups and gets that
 * miss L1 read it, all synchronously on the event loop.  So the jar is kept
 * bounded, like RFC 6265 6.1 expects of a user agent: these apply when the
 * creation info does not give max_items / max_footprint / max_payload.  When
 * over, the oldest lines go: we add new lines at the start of the file.
 */
#define NSC_DEFAULT_MAX_LINES		3000
#define NSC_DEFAULT_MAX_BYTES		(1024 * 1024)
#define NSC_DEFAULT_MAX_PAYLOAD		8192
#define NSC_MAX_LINES_PER_HOST		50

/*
 * Nothing holds the jar lock for longer than one rewrite, so a lock file
 * older than this was left by a process that died holding it
 */
#define NSC_LOCK_STALE_SECS		30

/*
 * The jar path plus ".LCK" or ".tmp" has to fit in this.  create() refuses a
 * jar path that does not, since a truncated sibling path could be the jar
 * itself, or some other file, that we would then lock, rewrite or unlink.
 */
#define NSC_PATH_MAX			256

static int
nsc_sibling_path(lws_cache_nscookiejar_t *cache, char *buf, size_t len,
		 const char *suffix)
{
	/* lws_snprintf() reports a truncated result as the whole size */
	return lws_snprintf(buf, len, "%s%s",
			    cache->cache.info.u.nscookiejar.filepath, suffix) >=
								(int)len;
}

static void
expiry_cb(lws_sorted_usec_list_t *sul);

/*
 * We are on the event loop, so we never wait for another process to finish
 * with the jar: if it has the lock, this operation fails like any other jar
 * error would (the caller still has L1, and the expiry sweep comes again).
 */

static int
nsc_lock(const char *lock)
{
	struct stat s;
	int fd_lock;

	fd_lock = open(lock, LWS_O_CREAT | O_EXCL, 0600);
	if (fd_lock < 0 && errno == EEXIST && !stat(lock, &s) &&
	    time(NULL) - s.st_mtime > NSC_LOCK_STALE_SECS) {
		lwsl_notice("%s: removing stale %s\n", __func__, lock);
		unlink(lock);
		fd_lock = open(lock, LWS_O_CREAT | O_EXCL, 0600);
	}

	if (fd_lock < 0)
		return 1;

	close(fd_lock);

	return 0;
}

static int
nsc_backing_open_lock(lws_cache_nscookiejar_t *cache, int mode, const char *par)
{
	char lock[NSC_PATH_MAX];
	int fd;

	lwsl_debug("%s: %s\n", __func__, par);

	if (nsc_sibling_path(cache, lock, sizeof(lock), ".LCK"))
		return -1;

	if (nsc_lock(lock)) {
		lwsl_info("%s: %s: jar busy, errno %d\n", __func__, par, errno);
		return -1;
	}

	fd = open(cache->cache.info.u.nscookiejar.filepath,
		      LWS_O_CREAT | mode, 0600);

	if (fd == -1) {
		lwsl_warn("%s: unable to open or create %s\n", __func__,
				cache->cache.info.u.nscookiejar.filepath);
		unlink(lock);
	}

	return fd;
}

static void
nsc_backing_close_unlock(lws_cache_nscookiejar_t *cache, int fd)
{
	char lock[NSC_PATH_MAX];

	lwsl_debug("%s\n", __func__);

	if (fd >= 0)
		close(fd);
	if (nsc_sibling_path(cache, lock, sizeof(lock), ".LCK"))
		return; /* we can't have locked it either */
	unlink(lock);
}

/*
 * We're going to call the callback with chunks of the file with flags
 * indicating we're giving it the start of a line and / or giving it the end
 * of a line.
 *
 * It's like this because the cookie value may be huge (and to a lesser extent
 * the path may also be big).
 *
 * If it's the start of a line (flags on the cb has LCN_SOL), then the buffer
 * contains up to the first 255 chars of the line, it's enough to match with.
 * Lines starting with '#' are comments and are skipped whatever their length.
 * The callback never sees the '\n' itself.
 *
 * Only running out of file ends the walk: a long or empty line, or a buffer
 * that happens to be full, must never look like the end of the file, since
 * nsc_regen() replaces the jar with whatever the walk passed through.  A read
 * error fails the walk.
 *
 * We cannot hold the file open inbetweentimes, since other processes may
 * regenerate it, so we need to bind to a new inode.  We open it with an
 * exclusive flock() so other processes can't replace conflicting changes
 * while we also write changes, without having to wait and see our changes.
 */

static int
nscookiejar_iterate(lws_cache_nscookiejar_t *cache, int fd,
		    nsc_cb_t cb, void *opaque)
{
	int r = LCN_SOL, e;
	char temp[NSC_LINE_BUF], eof = 0, skip = 0;
	size_t n = 0; /* bytes held in temp */

	if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
		return NIR_FINISH_ERROR;

	while (1) {
		const char *eol;
		size_t len;

		if (!eof && n < sizeof(temp)) {
			ssize_t n1s = read(fd, temp + n,
					  LWS_POSIX_LENGTH_CAST(sizeof(temp) - n));

			if (n1s < 0) {
				if (errno == EINTR)
					continue;
				/* we can't tell what we are missing */
				return NIR_FINISH_ERROR;
			}
			if (!n1s)
				eof = 1;
			else
				n += (size_t)n1s;
		}

		if (!n) /* ie, eof with nothing left over */
			return 0;

		if (r & LCN_SOL)
			skip = temp[0] == '#';

		eol = (const char *)memchr(temp, '\n', n);
		if (eol) {
			/* deliver the rest of the line, and consume the '\n' */

			len = lws_ptr_diff_size_t(eol, temp);
			e = skip ? 0 : cb(cache, opaque, r | LCN_EOL, temp, len);

			n -= len + 1;
			memmove(temp, eol + 1, n);
			r = LCN_SOL;
			if (e)
				return e;

			continue;
		}

		if (!eof && n < sizeof(temp))
			/* there's room for more of this line, read it */
			continue;

		if (eof) {
			/* the last line has no '\n', deliver it all as the end */

			e = skip ? 0 : cb(cache, opaque, r | LCN_EOL, temp, n);
			if (e)
				return e;
			n = 0;
			r = LCN_SOL;

			continue;
		}

		/*
		 * The buffer is full of one line and there is more of it.  Pass
		 * on all but the last byte, keeping it back so the chunk that
		 * ends the line is never empty
		 */

		e = skip ? 0 : cb(cache, opaque, r, temp, n - 1);
		temp[0] = temp[n - 1];
		n = 1;
		r = 0;
		if (e)
			return e;
	}
}

/*
 * lookup() just handles wildcard resolution, it doesn't deal with moving the
 * hits to L1.  That has to be done individually by non-wildcard names.
 */

enum {
	NSC_COL_HOST		= 0, /* wc idx 0 */
	NSC_COL_PATH		= 2, /* wc idx 1 */
	NSC_COL_EXPIRY		= 4,
	NSC_COL_NAME		= 5, /* wc idx 2 */

	NSC_COL_COUNT		= 6
};

/*
 * This performs the specialized wildcard that knows about cookie path match
 * rules.
 *
 * To defeat the lookup path matching, lie to it about idx being NSC_COL_PATH
 */

static int
nsc_match(const char *wc, size_t wc_len, const char *col, size_t col_len,
	  int idx)
{
	size_t n = 0;

	if (idx != NSC_COL_PATH)
		return lws_strcmp_wildcard(wc, wc_len, col, col_len);

	/*
	 * Cookie path match is special, if we lookup on a path like /my/path,
	 * we must match on cookie paths for every dir level including /, so
	 * match on /, /my, and /my/path.  But we must not match on /m or
	 * /my/pa etc.  If we lookup on /, we must not match /my/path
	 *
	 * Let's go through wc checking at / and for every complete subpath if
	 * it is an explicit match
	 */

	if (!strcmp(col, wc))
		return 0; /* exact hit */

	while (n <= wc_len) {
		if (n == wc_len || wc[n] == '/') {
			if (n && col_len <= n && !strncmp(wc, col, n))
				return 0; /* hit */

			if (n != wc_len && col_len <= n + 1 &&
			    !strncmp(wc, col, n + 1)) /* check for trailing / */
				return 0; /* hit */
		}
		n++;
	}

	return 1; /* fail */
}

static const uint8_t nsc_cols[] = { NSC_COL_HOST, NSC_COL_PATH, NSC_COL_NAME };

static int
lws_cache_nscookiejar_tag_match(struct lws_cache_ttl_lru *cache,
				const char *wc, const char *tag, char lookup)
{
	const char *wc_end = wc + strlen(wc), *tag_end = tag + strlen(tag),
			*start_wc, *start_tag;
	int n = 0;

	lwsl_cache("%s: '%s' vs '%s'\n", __func__, wc, tag);

	/*
	 * Given a well-formed host|path|name tag and a wildcard term,
	 * make the determination if the tag matches the wildcard or not,
	 * using lookup rules that apply at this cache level.
	 */

	while (n < 3) {
		start_wc = wc;
		while (wc < wc_end && *wc != LWSCTAG_SEP)
			wc++;

		start_tag = tag;
		while (tag < tag_end && *tag != LWSCTAG_SEP)
			tag++;

		lwsl_cache("%s:   '%.*s' vs '%.*s'\n", __func__,
				lws_ptr_diff(wc, start_wc), start_wc,
				lws_ptr_diff(tag, start_tag), start_tag);
		if (nsc_match(start_wc, lws_ptr_diff_size_t(wc, start_wc),
			      start_tag, lws_ptr_diff_size_t(tag, start_tag),
			      lookup ? nsc_cols[n] : NSC_COL_HOST)) {
			lwsl_cache("%s: fail\n", __func__);
			return 1;
		}

		if (wc < wc_end)
			wc++;
		if (tag < tag_end)
			tag++;

		n++;
	}

	lwsl_cache("%s: hit\n", __func__);

	return 0; /* match */
}

/*
 * Converts the start of a cookie file line into a tag, and optionally its
 * expiry.  buf holds the start of the line, whole_line says if it is all of
 * it, or if the line goes on after buf (and so the name column must end with
 * its TAB inside buf, or we would index a truncated name).
 *
 * Columns are never truncated: a line whose tag would not fit in max_tag, or
 * whose tag columns are not all in buf, is reported NSC_LTT_TOO_LONG.
 */

/*
 * Expiries are kept in the time of the service thread the cache sul runs on
 * (lws_service_set_now() may make that differ from the platform clock)
 */

static lws_usec_t
nsc_now(lws_cache_nscookiejar_t *cache)
{
	return lws_cx_now(cache->cache.info.cx, cache->cache.info.tsi);
}

static int
nsc_line_to_tag(lws_cache_nscookiejar_t *cache, const char *buf, size_t size,
		int whole_line, char *tag, size_t max_tag, lws_usec_t *pexpiry)
{
	size_t bn = 0, tl = 0, cs, cl, n;
	lws_usec_t expiry = 0;
	uint64_t secs = 0;
	int idx;

	for (idx = 0; idx < NSC_COL_COUNT; idx++) {

		/* find the extent of this column */

		cs = bn;
		while (bn < size && buf[bn] != '\t')
			bn++;
		cl = bn - cs;

		if (bn == size && (idx != NSC_COL_NAME || !whole_line)) {
			/*
			 * We ran out of line (or of what we were given of it)
			 * before the end of the columns we need
			 */
			if (whole_line)
				return NSC_LTT_MALFORMED;

			return NSC_LTT_TOO_LONG;
		}
		bn++; /* the TAB */

		switch (idx) {
		case NSC_COL_EXPIRY:
			/*
			 * The on-disk expiry is wall-clock seconds since the
			 * Unix epoch. A value of 0 is the "session cookie /
			 * no expiry" sentinel and is passed through unchanged.
			 * Parse it unsigned and clamp it, so the conversion
			 * below cannot overflow.
			 */
			if (!cl)
				return NSC_LTT_MALFORMED;
			for (n = cs; n < cs + cl; n++) {
				if (buf[n] < '0' || buf[n] > '9')
					return NSC_LTT_MALFORMED;
				if (secs <= NSC_EXPIRY_MAX_SECS)
					secs = (secs * 10) +
					       (uint64_t)(buf[n] - '0');
			}
			if (secs > NSC_EXPIRY_MAX_SECS)
				secs = NSC_EXPIRY_MAX_SECS;
			break;

		case NSC_COL_HOST:
		case NSC_COL_PATH:
		case NSC_COL_NAME:

			/* compose the tag, "host|path|name" */

			if (tl + (tl ? 1u : 0u) + cl + 1u > max_tag)
				return NSC_LTT_TOO_LONG;
			if (tl)
				tag[tl++] = LWSCTAG_SEP;
			memcpy(tag + tl, buf + cs, cl);
			tl += cl;
			tag[tl] = '\0';
			break;

		default:
			break;
		}
	}

	if (secs && pexpiry)
		expiry = nsc_now(cache) + ((lws_usec_t)secs -
					   (lws_usec_t)time(NULL)) *
					  LWS_US_PER_SEC;

	if (pexpiry)
		*pexpiry = expiry;

	lwsl_cache("%s: tag '%s'\n", __func__, tag);

	return NSC_LTT_OK;
}

struct nsc_lookup_ctx {
	const char		*wildcard_key;
	lws_dll2_owner_t	*results_owner;
	lws_cache_match_t	*match; /* current match if any */
	size_t			wklen;
};


static int
nsc_lookup_cb(lws_cache_nscookiejar_t *cache, void *opaque, int flags,
	      const char *buf, size_t size)
{
	struct nsc_lookup_ctx *ctx = (struct nsc_lookup_ctx *)opaque;
	char tag[NSC_TAG_MAX];
	lws_usec_t expiry;
	int tl;

	if (!(flags & LCN_SOL)) {
		if (ctx->match)
			ctx->match->payload_size += size;

		return NIR_CONTINUE;
	}

	/*
	 * There should be enough in buf to match or reject it... let's
	 * synthesize a tag from the text "line" and then check the tags for
	 * a match
	 */

	ctx->match = NULL; /* new SOL means stop tracking payload len */

	if (nsc_line_to_tag(cache, buf, size, !!(flags & LCN_EOL), tag,
			    sizeof(tag), &expiry) ||
	    (expiry && expiry <= nsc_now(cache)))
		/* not indexable, or expired and not yet swept */
		return NIR_CONTINUE;

	if (lws_cache_nscookiejar_tag_match(&cache->cache,
					    ctx->wildcard_key, tag, 1))
		return NIR_CONTINUE;

	tl = (int)strlen(tag);

	/*
	 * ... it looks like a match then... create new match
	 * object with the specific tag, and add it to the owner list
	 */

	ctx->match = lws_fi(&cache->cache.info.cx->fic, "cache_lookup_oom") ? NULL :
			lws_malloc(sizeof(*ctx->match) + (unsigned int)tl + 1u,
				__func__);
	if (!ctx->match)
		/* caller of lookup will clean results list on fail */
		return NIR_FINISH_ERROR;

	ctx->match->payload_size = size;
	ctx->match->tag_size = (size_t)tl;
	ctx->match->expiry = expiry;

	memset(&ctx->match->list, 0, sizeof(ctx->match->list));
	memcpy(&ctx->match[1], tag, (size_t)tl + 1u);
	lws_dll2_add_tail(&ctx->match->list, ctx->results_owner);

	return NIR_CONTINUE;
}

static int
lws_cache_nscookiejar_lookup(struct lws_cache_ttl_lru *_c,
			     const char *wildcard_key,
			     lws_dll2_owner_t *results_owner)
{
	lws_cache_nscookiejar_t *cache = (lws_cache_nscookiejar_t *)_c;
	struct nsc_lookup_ctx ctx;
	int ret, fd;

	fd = nsc_backing_open_lock(cache, LWS_O_RDONLY, __func__);
	if (fd < 0)
		return 1;

	ctx.wildcard_key = wildcard_key;
	ctx.results_owner = results_owner;
	ctx.wklen = strlen(wildcard_key);
	ctx.match = 0;

	ret = nscookiejar_iterate(cache, fd, nsc_lookup_cb, &ctx);
		/*
		 * The cb can fail, eg, with OOM, making the whole lookup
		 * invalid and returning fail.  Caller will clean
		 * results_owner on fail.
		 */
	nsc_backing_close_unlock(cache, fd);

	return ret == NIR_FINISH_ERROR;
}

/*
 * It's pretty horrible having to implement add or remove individual items by
 * file regeneration, but if we don't want to keep it all in heap, and we want
 * this cookie jar format, that is what we are into.
 *
 * Allow to optionally add a "line", optionally wildcard delete tags, and always
 * delete expired entries.
 *
 * Although we can rely on the lws thread to be doing this, multiple processes
 * may be using the cookie jar and can tread on each other.  So we use flock()
 * (linux only) to get exclusive access while we are processing this.
 *
 * We leave the existing file alone and generate a new one alongside it, with a
 * fixed name.tmp format so it can't leak, if that went OK then we unlink the
 * old and rename the new.
 */

struct nsc_regen_ctx {
	const char		*specific_key_delete;
	const char		*add_host; /* host column of the added line */
	lws_usec_t		curr;
	size_t			add_host_len;
	size_t			lines; /* lines kept so far */
	size_t			max_lines;
	size_t			max_bytes;
	size_t			host_lines; /* kept for add_host so far */
	int			fdt;
	char			drop;
};

/* only used by nsc_regen() */

static int
nsc_regen_cb(lws_cache_nscookiejar_t *cache, void *opaque, int flags,
	      const char *buf, size_t size)
{
	struct nsc_regen_ctx *ctx = (struct nsc_regen_ctx *)opaque;
	char tag[NSC_TAG_MAX];
	lws_usec_t expiry;

	if (flags & LCN_SOL) {

		ctx->drop = 0;

		switch (nsc_line_to_tag(cache, buf, size, !!(flags & LCN_EOL),
					tag, sizeof(tag), &expiry)) {
		case NSC_LTT_OK:
			break;
		case NSC_LTT_TOO_LONG:
			/*
			 * Somebody else's line we cannot index: it is not ours
			 * to delete, keep it as it is (within the limits)
			 */
			expiry = 0;
			goto limits;
		default:
			/* filter it out if it is unparseable */
			goto drop;
		}

		if (expiry && expiry <= ctx->curr)
			/* routinely strip anything beyond its expiry */
			goto drop;

		/* a specific key is matched literally, never as a wildcard */

		if (ctx->specific_key_delete &&
		    !strcmp(ctx->specific_key_delete, tag)) {
			lwsl_cache("%s: dropping %s\n", __func__, tag);
			goto drop;
		}

		/*
		 * The line we are adding went first, so a host that has too
		 * many already loses its oldest ones
		 */

		if (ctx->add_host &&
		    !strncmp(tag, ctx->add_host, ctx->add_host_len) &&
		    tag[ctx->add_host_len] == LWSCTAG_SEP &&
		    ++ctx->host_lines > NSC_MAX_LINES_PER_HOST)
			goto drop;

limits:
		/* newest lines are first, so the oldest go past the limits */

		if (ctx->lines >= ctx->max_lines ||
		    cache->cache.current_footprint >= ctx->max_bytes)
			goto drop;
		ctx->lines++;

		/* track the earliest expiry of what we keep */

		if (expiry && (!cache->earliest_expiry ||
			       cache->earliest_expiry > expiry))
			cache->earliest_expiry = expiry;
	}

	if (ctx->drop)
		return 0;

	cache->cache.current_footprint += (uint64_t)size;

	if (write(ctx->fdt, buf, LWS_POSIX_LENGTH_CAST(size)) != (ssize_t)size)
		return NIR_FINISH_ERROR;

	if (flags & LCN_EOL)
		if ((size_t)write(ctx->fdt, "\n", 1) != 1)
			return NIR_FINISH_ERROR;

	return 0;

drop:
	ctx->drop = 1;

	return NIR_CONTINUE;
}

static int
nsc_regen(lws_cache_nscookiejar_t *cache, const char *specific_key_delete,
	  const void *pay, size_t pay_size)
{
	struct nsc_regen_ctx ctx;
	char filepath[NSC_PATH_MAX];
	int fd, ret = 1;

	memset(&ctx, 0, sizeof(ctx));
	ctx.fdt = -1;

	fd = nsc_backing_open_lock(cache, LWS_O_RDONLY, __func__);
	if (fd < 0)
		return 1;

	if (nsc_sibling_path(cache, filepath, sizeof(filepath), ".tmp")) {
		nsc_backing_close_unlock(cache, fd);
		return 1;
	}
	unlink(filepath);

	if (lws_fi(&cache->cache.info.cx->fic, "cache_regen_temp_open"))
		goto bail;

	/*
	 * Exclusively: if something appeared at the tmp path since the unlink
	 * (eg, planted by another user in a shared dir), we must not write the
	 * jar through it
	 */
	ctx.fdt = open(filepath, LWS_O_CREAT | O_EXCL | LWS_O_WRONLY, 0600);
	if (ctx.fdt < 0)
		goto bail;

	/* magic header */

	if (lws_fi(&cache->cache.info.cx->fic, "cache_regen_temp_write") ||
	/* other consumers insist to see this at start of cookie jar */
	    write(ctx.fdt, "# Netscape HTTP Cookie File\n", 28) != 28)
		goto bail1;

	/* if we are adding something, put it first */

	if (pay &&
	    write(ctx.fdt, pay, LWS_POSIX_LENGTH_CAST(pay_size)) !=
						    (ssize_t)pay_size)
		goto bail1;
	if (pay && write(ctx.fdt, "\n", 1u) != (ssize_t)1)
		goto bail1;

	cache->cache.current_footprint = pay ? (uint64_t)pay_size + 1u : 0u;

	ctx.specific_key_delete = specific_key_delete;
	ctx.curr = nsc_now(cache);
	ctx.max_lines = cache->cache.info.max_items ?
			cache->cache.info.max_items : NSC_DEFAULT_MAX_LINES;
	ctx.max_bytes = cache->cache.info.max_footprint ?
			cache->cache.info.max_footprint : NSC_DEFAULT_MAX_BYTES;

	if (pay) {
		const char *tab = memchr(pay, '\t', pay_size);

		/* write() only lets well-formed lines through */
		ctx.add_host = (const char *)pay;
		ctx.add_host_len = tab ? lws_ptr_diff_size_t(tab, pay) : 0;
		ctx.host_lines = 1; /* the one we are adding */
		ctx.lines = 1;
	}

	cache->earliest_expiry = 0;

	if (lws_fi(&cache->cache.info.cx->fic, "cache_regen_iter_fail") ||
	    nscookiejar_iterate(cache, fd, nsc_regen_cb, &ctx))
		goto bail1;

	close(ctx.fdt);
	ctx.fdt = -1;

#if defined(WIN32)
	/*
	 * On Windows, unlink / rename fail while fd holds the original
	 * file open for reading.  Close it first so the replace can
	 * succeed.  nsc_backing_close_unlock() checks fd >= 0, so
	 * setting it to -1 makes the later close a safe no-op.
	 */
	close(fd);
	fd = -1;
#endif

	if (unlink(cache->cache.info.u.nscookiejar.filepath) == -1)
		lwsl_info("%s: unlink %s failed\n", __func__,
			  cache->cache.info.u.nscookiejar.filepath);
	if (rename(filepath, cache->cache.info.u.nscookiejar.filepath) == -1)
		lwsl_info("%s: rename %s failed\n", __func__,
			  cache->cache.info.u.nscookiejar.filepath);

	if (cache->earliest_expiry)
		lws_cache_schedule(&cache->cache, expiry_cb,
				   cache->earliest_expiry);

	ret = 0;
	goto bail;

bail1:
	if (ctx.fdt >= 0)
		close(ctx.fdt);
bail:
	unlink(filepath);

	nsc_backing_close_unlock(cache, fd);

	return ret;
}

static void
expiry_cb(lws_sorted_usec_list_t *sul)
{
	lws_cache_nscookiejar_t *cache = (lws_cache_nscookiejar_t *)
			lws_container_of(sul, lws_cache_ttl_lru_t, sul);

	lws_cache_lock(&cache->cache); /* ---------------------- cache { */

	/*
	 * regen the cookie jar without changes, so expired are removed and
	 * new earliest expired computed
	 */
	if (!nsc_regen(cache, NULL, NULL, 0) && cache->earliest_expiry)
		lws_cache_schedule(&cache->cache, expiry_cb,
				   cache->earliest_expiry);

	lws_cache_unlock(&cache->cache); /* --------------------- } cache */
}


/*
 * The jar is a line-oriented text file shared with other cookie consumers,
 * and its lines are built from fields a server chose.  Only accept a line
 * that stays one well-formed line, whose tag is exactly the key the upper
 * levels know it by, and whose tag fields contain nothing that could be read
 * back as a wildcard or a field separator.
 */

static int
nsc_line_acceptable(const char *line, size_t size, const char *tag,
		    const char *specific_key)
{
	int seps = 0;

	if (!size || line[0] == '#' || memchr(line, '\n', size) ||
	    memchr(line, '\r', size) || memchr(line, '\0', size))
		return 0;

	if (specific_key && strcmp(specific_key, tag))
		/* eg, a TAB inside a field shifted the columns */
		return 0;

	while (*tag) {
		if (*tag == '*' || *tag == '?')
			return 0;
		if (*tag == LWSCTAG_SEP)
			seps++;
		tag++;
	}

	return seps == 2;
}

/* expiry is ignored, since it must be encoded in payload */

static int
lws_cache_nscookiejar_write(struct lws_cache_ttl_lru *_c,
			    const char *specific_key, const uint8_t *source,
			    size_t size, lws_usec_t expiry, void **ppvoid)
{
	lws_cache_nscookiejar_t *cache = (lws_cache_nscookiejar_t *)_c;
	char tag[NSC_TAG_MAX];

	lwsl_cache("%s: %s: len %d\n", __func__, _c->info.name, (int)size);

	assert(source);

	if (size > (_c->info.max_payload ? _c->info.max_payload :
					   NSC_DEFAULT_MAX_PAYLOAD)) {
		lwsl_info("%s: refusing %u byte jar line\n", __func__,
			  (unsigned int)size);
		return 1;
	}

	/*
	 * Parse it the way it will be seen when read back, so we only store
	 * lines we will be able to find and remove again
	 */

	if (nsc_line_to_tag(cache, (const char *)source,
			    size > NSC_SOL_MAX ? NSC_SOL_MAX : size,
			    size <= NSC_SOL_MAX, tag, sizeof(tag), NULL))
		return 1;

	if (!nsc_line_acceptable((const char *)source, size, tag,
				 specific_key)) {
		lwsl_warn("%s: refusing unsafe jar line\n", __func__);
		return 1;
	}

	if (ppvoid)
		*ppvoid = NULL;

	if (nsc_regen(cache, tag, source, size)) {
		lwsl_warn("%s: regen failed\n", __func__);

		return 1;
	}

	return 0;
}

struct nsc_get_ctx {
	struct lws_buflist	*buflist;
	const char		*specific_key;
	const void		**pdata;
	size_t			*psize;
	lws_cache_ttl_lru_t	*l1;
	lws_usec_t		expiry;
};

/*
 * We're looking for a specific key, if found, we want to make an entry for it
 * in L1 and return information about that
 */

static int
nsc_get_cb(lws_cache_nscookiejar_t *cache, void *opaque, int flags,
	   const char *buf, size_t size)
{
	struct nsc_get_ctx *ctx = (struct nsc_get_ctx *)opaque;
	char tag[NSC_TAG_MAX];
	uint8_t *q;

	if (ctx->buflist)
		goto collect;

	if (!(flags & LCN_SOL))
		return NIR_CONTINUE;

	if (nsc_line_to_tag(cache, buf, size, !!(flags & LCN_EOL), tag,
			    sizeof(tag), &ctx->expiry) ||
	    (ctx->expiry && ctx->expiry <= nsc_now(cache)))
		/*
		 * not a line we can index, so it can't be the one we want, or
		 * it has expired and not been swept yet
		 */
		return NIR_CONTINUE;

	lwsl_cache("%s: %s %s\n", __func__, ctx->specific_key, tag);

	if (strcmp(ctx->specific_key, tag)) {
		lwsl_cache("%s: no match\n", __func__);
		return NIR_CONTINUE;
	}

	/* it's a match */

	lwsl_cache("%s: IS match\n", __func__);

	if (!(flags & LCN_EOL))
		goto collect;

	/* it all fit in the buffer, let's create it in L1 now */

	*ctx->psize = size;
	if (ctx->l1->info.ops->write(ctx->l1,
				     ctx->specific_key, (const uint8_t *)buf,
				     size, ctx->expiry, (void **)ctx->pdata))
		return NIR_FINISH_ERROR;

	return NIR_FINISH_OK;

collect:
	/*
	 * it's bigger than one buffer-load, we have to stash what we're getting
	 * on a buflist and create it when we have it all.  The append returns
	 * 1 for the first segment on the list, only < 0 is a failure.
	 */

	if (size && lws_buflist_append_segment(&ctx->buflist,
					       (const uint8_t *)buf, size) < 0)
		goto cleanup;

	if (!(flags & LCN_EOL))
		return NIR_CONTINUE;

	/* we have all the payload, create the L1 entry without payload yet */

	*ctx->psize = lws_buflist_total_len(&ctx->buflist);
	if (ctx->l1->info.ops->write(ctx->l1, ctx->specific_key, NULL,
				     *ctx->psize, ctx->expiry, (void **)&q))
		goto cleanup;
	*ctx->pdata = q;

	/* dump the buflist into the L1 cache entry */

	do {
		uint8_t *p;
		size_t len = lws_buflist_next_segment_len(&ctx->buflist, &p);

		memcpy(q, p, len);
		q += len;

		lws_buflist_use_segment(&ctx->buflist, len);
	} while (ctx->buflist);

	return NIR_FINISH_OK;

cleanup:
	lws_buflist_destroy_all_segments(&ctx->buflist);

	return NIR_FINISH_ERROR;
}

static int
lws_cache_nscookiejar_get(struct lws_cache_ttl_lru *_c,
			  const char *specific_key, const void **pdata,
			  size_t *psize)
{
	lws_cache_nscookiejar_t *cache = (lws_cache_nscookiejar_t *)_c;
	struct nsc_get_ctx ctx;
	int ret, fd;

	fd = nsc_backing_open_lock(cache, LWS_O_RDONLY, __func__);
	if (fd < 0)
		return 1;

	/* get a pointer to l1 */
	ctx.l1 = &cache->cache;
	while (ctx.l1->child)
		ctx.l1 = ctx.l1->child;

	ctx.pdata = pdata;
	ctx.psize = psize;
	ctx.specific_key = specific_key;
	ctx.buflist = NULL;
	ctx.expiry = 0;

	ret = nscookiejar_iterate(cache, fd, nsc_get_cb, &ctx);

	nsc_backing_close_unlock(cache, fd);

	return ret != NIR_FINISH_OK;
}

static int
lws_cache_nscookiejar_invalidate(struct lws_cache_ttl_lru *_c,
				 const char *specific_key)
{
	lws_cache_nscookiejar_t *cache = (lws_cache_nscookiejar_t *)_c;

	return nsc_regen(cache, specific_key, NULL, 0);
}

static struct lws_cache_ttl_lru *
lws_cache_nscookiejar_create(const struct lws_cache_creation_info *info)
{
	lws_cache_nscookiejar_t *cache;

	if (!info->u.nscookiejar.filepath ||
	    strlen(info->u.nscookiejar.filepath) + 4 /* ".LCK" */ >=
							NSC_PATH_MAX) {
		lwsl_err("%s: jar path too long\n", __func__);
		return NULL;
	}

	cache = lws_fi(&info->cx->fic, "cache_createfail") ? NULL :
					lws_zalloc(sizeof(*cache), __func__);
	if (!cache)
		return NULL;

	lws_cache_base_init(&cache->cache, info);

	/*
	 * We need to scan the file, if it exists, and find the earliest
	 * expiry while cleaning out any expired entries
	 */
	expiry_cb(&cache->cache.sul);

	lwsl_info("%s: create %s\n", __func__, info->name ? info->name : "?");

	return (struct lws_cache_ttl_lru *)cache;
}

static int
lws_cache_nscookiejar_expunge(struct lws_cache_ttl_lru *_c)
{
	lws_cache_nscookiejar_t *cache = (lws_cache_nscookiejar_t *)_c;
	int r;

	if (!cache)
		return 0;

	r = unlink(cache->cache.info.u.nscookiejar.filepath);
	if (r)
		lwsl_warn("%s: failed to unlink %s\n", __func__,
				cache->cache.info.u.nscookiejar.filepath);

	return r;
}

static void
lws_cache_nscookiejar_destroy(struct lws_cache_ttl_lru **_pc)
{
	lws_cache_nscookiejar_t *cache = (lws_cache_nscookiejar_t *)*_pc;

	if (!cache)
		return;

	lws_sul_cancel(&cache->cache.sul);

	lws_free_set_NULL(*_pc);
}

#if defined(_DEBUG)

static int
nsc_dump_cb(lws_cache_nscookiejar_t *cache, void *opaque, int flags,
	      const char *buf, size_t size)
{
	lwsl_hexdump_cache(buf, size);

	return 0;
}

static void
lws_cache_nscookiejar_debug_dump(struct lws_cache_ttl_lru *_c)
{
	lws_cache_nscookiejar_t *cache = (lws_cache_nscookiejar_t *)_c;
	int fd = nsc_backing_open_lock(cache, LWS_O_RDONLY, __func__);

	if (fd < 0)
		return;

	lwsl_cache("%s: %s\n", __func__, _c->info.name);

	nscookiejar_iterate(cache, fd, nsc_dump_cb, NULL);

	nsc_backing_close_unlock(cache, fd);
}
#endif

const struct lws_cache_ops lws_cache_ops_nscookiejar = {
	.create			= lws_cache_nscookiejar_create,
	.destroy		= lws_cache_nscookiejar_destroy,
	.expunge		= lws_cache_nscookiejar_expunge,

	.write			= lws_cache_nscookiejar_write,
	.tag_match		= lws_cache_nscookiejar_tag_match,
	.lookup			= lws_cache_nscookiejar_lookup,
	.invalidate		= lws_cache_nscookiejar_invalidate,
	.get			= lws_cache_nscookiejar_get,
#if defined(_DEBUG)
	.debug_dump		= lws_cache_nscookiejar_debug_dump,
#endif
};
