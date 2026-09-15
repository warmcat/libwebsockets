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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * lws_cache_ttl_lru level that stores arbitrary binary blobs as one hashed
 * file per item, in the hashed cache dir layout used by lws_diskcache.
 *
 * Storage format at "<dir>/<h0>/<h1>/<sha1(key) hex>":
 *
 *   4 bytes  magic "LWSB"
 *   8 bytes  BE64 usec expiry (0 = never expires)
 *   4 bytes  BE32 payload length
 *   ...      payload bytes
 *
 * There is no in-memory index of what is on disk: the item key is hashed to
 * its filename and the header is read back from the file itself.  Keeping the
 * cache under its size limit and removing expired leftovers is done by a
 * recurring sul that calls lws_diskcache_trim()... this statefully walks one
 * cache subdir per call and, once it has seen everything, deletes up to
 * BATCH_COUNT of the oldest files if the aggregate is over the limit.  The
 * work is spread in time, so the cache never blocks the event loop with a
 * mass deletion pass.
 *
 * Because item keys only exist on disk as hashes, it is not possible to
 * enumerate keys matching a wildcard: lookup() always produces no results and
 * invalidate() can only act on specific, wildcard-free keys.  Expiry is
 * enforced when the item is got, by dropping the stale file.
 */

#include <private-lib-core.h>
#include "private-lib-misc-cache-ttl.h"

#include <sys/stat.h>

#if defined(write)
#undef write
#endif

/*
 * How long between maintenance passes when the trimmer says the cache is
 * oversize (lws_diskcache_secs_to_idle() returning 0).  Each pass visits one
 * subdir, so at this spacing a whole scan cycle takes ~2.5s without ever
 * doing more than one readdir + a few stats of work at once.
 */

#define BLOB_MAINTAIN_URGENT_US		(10 * LWS_US_PER_MS)

/* first maintenance pass delay at cache creation */

#define BLOB_MAINTAIN_FIRST_US		LWS_US_PER_SEC

#define BLOB_HDR_LEN			16

static const uint8_t blob_magic[4] = { 'L', 'W', 'S', 'B' };

typedef struct lws_cache_blob {
	lws_cache_ttl_lru_t		cache; /* base class */
	struct lws_diskcache_scan	*lds;
} lws_cache_blob_t;

static const char *hexchars = "0123456789abcdef";

/*
 * The item key is attacker-influenced (it comes from document URLs), so it is
 * never used as a filename directly: the filename is the hex sha1 of the key.
 */

static int
blob_hash_key(const char *key, char hex[41])
{
	uint8_t digest[LWS_GENHASH_LARGEST];
	const uint8_t *d;
	char *p = hex;

	lws_SHA1((const unsigned char *)key, strlen(key), digest);

	for (d = digest; d < digest + 20; d++) {
		*p++ = hexchars[*d >> 4];
		*p++ = hexchars[*d & 15];
	}
	*p = '\0';

	return 0;
}

static int
blob_write(int fd, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;

	while (len) {
		ssize_t n = write(fd, p, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return 1;
		}
		p += n;
		len -= (size_t)n;
	}

	return 0;
}

static int
blob_read(int fd, void *buf, size_t len)
{
	uint8_t *p = (uint8_t *)buf;

	while (len) {
		ssize_t n = read(fd, p, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return 1;
		}
		if (!n)
			return 1;
		p += n;
		len -= (size_t)n;
	}

	return 0;
}

/*
 * Create "<base>/[0-f]/[0-f]" the hashed layout the trimmer walks.  It does
 * not matter if they are already there.
 */

static int
blob_prepare_dirs(const char *base)
{
	char dir[256];
	int n, m;

	if (mkdir(base, 0700) && errno != EEXIST)
		return 1;

	for (n = 0; n < 16; n++) {
		lws_snprintf(dir, sizeof(dir), "%s/%c", base, hexchars[n]);
		if (mkdir(dir, 0700) && errno != EEXIST)
			return 1;

		for (m = 0; m < 16; m++) {
			lws_snprintf(dir, sizeof(dir), "%s/%c/%c", base,
				     hexchars[n], hexchars[m]);
			if (mkdir(dir, 0700) && errno != EEXIST)
				return 1;
		}
	}

	return 0;
}

/*
 * The recurring self-maintenance pass.  One call does one subdir of readdir +
 * stats, or, if the previous full scan found the cache oversize, up to
 * BATCH_COUNT unlinks of the oldest files.  When it is content, the trimmer
 * says how long to idle before the next pass.
 */

static void
blob_maintain_cb(lws_sorted_usec_list_t *sul)
{
	lws_cache_blob_t *bc = lws_container_of(sul, lws_cache_blob_t,
						cache.sul);
	int secs;

	lws_diskcache_trim(bc->lds);

	secs = lws_diskcache_secs_to_idle(bc->lds);
	if (secs < 0)
		secs = 0;

	lws_sul_schedule(bc->cache.info.cx, bc->cache.info.tsi,
			 &bc->cache.sul, blob_maintain_cb,
			 secs ? (lws_usec_t)secs * LWS_US_PER_SEC
			      : BLOB_MAINTAIN_URGENT_US);
}

static struct lws_cache_ttl_lru *
lws_cache_blob_create(const struct lws_cache_creation_info *info)
{
	lws_cache_blob_t *bc;

	assert(info->cx);
	assert(info->name);
	assert(info->u.blob.dir);

	if (blob_prepare_dirs(info->u.blob.dir)) {
		lwsl_err("%s: unable to prepare %s\n", __func__,
			 info->u.blob.dir);
		return NULL;
	}

	bc = lws_fi(&info->cx->fic, "cache_createfail") ? NULL :
						lws_zalloc(sizeof(*bc), __func__);
	if (!bc)
		return NULL;

	bc->cache.info = *info;

	bc->lds = lws_diskcache_create(info->u.blob.dir,
				       info->max_footprint);
	if (!bc->lds) {
		lws_free(bc);
		return NULL;
	}

	lwsl_info("%s: created %s at %s, limit %llu\n", __func__, info->name,
		  info->u.blob.dir,
		  (unsigned long long)info->max_footprint);

	/* bring the dir under the limit in the background */

	lws_sul_schedule(bc->cache.info.cx, bc->cache.info.tsi,
			 &bc->cache.sul, blob_maintain_cb,
			 BLOB_MAINTAIN_FIRST_US);

	return &bc->cache;
}

static void
lws_cache_blob_destroy(struct lws_cache_ttl_lru **_cache)
{
	lws_cache_blob_t *bc = (lws_cache_blob_t *)*_cache;

	if (!bc)
		return;

	lws_sul_cancel(&bc->cache.sul);
	lws_diskcache_destroy(&bc->lds);

	lws_free_set_NULL(*_cache);
}

static int
lws_cache_blob_expunge(struct lws_cache_ttl_lru *_c)
{
	lws_cache_blob_t *bc = (lws_cache_blob_t *)_c;
	const char *base = bc->cache.info.u.blob.dir;

	/* remove the whole cache dir tree, then bring the layout back */

	lws_dir(base, NULL, lws_dir_rm_rf_cb);
	rmdir(base);

	bc->cache.current_footprint = 0;

	return blob_prepare_dirs(base);
}

static int
lws_cache_blob_write(struct lws_cache_ttl_lru *_c, const char *specific_key,
		     const uint8_t *source, size_t size, lws_usec_t expiry,
		     void **ppay)
{
	lws_cache_blob_t *bc = (lws_cache_blob_t *)_c;
	char path[256], hex[41];
	size_t extant;
	uint8_t hdr[BLOB_HDR_LEN];
	int fd, tries = 0;

	(void)ppay;

	/* we can only store the payload if we have it at write time */

	if (!source)
		return 1;

	if (bc->cache.info.max_payload &&
	    size > bc->cache.info.max_payload) {
		lwsl_info("%s: %s: too large to cache (%llu > %llu)\n",
			  __func__, specific_key,
			  (unsigned long long)size,
			  (unsigned long long)bc->cache.info.max_payload);
		return 1;
	}

	if (blob_hash_key(specific_key, hex))
		return 1;

again:
	switch (lws_diskcache_query(bc->lds, 0, hex, &fd, path,
				    sizeof(path), &extant)) {
	case LWS_DISKCACHE_QUERY_EXISTS:

		/* replace it: remove the old copy and try again */

		close(fd);
		unlink(path);
		if (tries++)
			return 1;
		goto again;

	case LWS_DISKCACHE_QUERY_CREATING:
		break;

	default:
		return 1;
	}

	memcpy(hdr, blob_magic, 4);
	lws_ser_wu64be(hdr + 4, (uint64_t)expiry);
	lws_ser_wu32be(hdr + 12, (uint32_t)size);

	if (blob_write(fd, hdr, sizeof(hdr)) ||
	    blob_write(fd, source, size)) {
		close(fd);
		unlink(path);

		return 1;
	}
	close(fd);

	if (lws_diskcache_finalize_name(path)) {
		unlink(path);

		return 1;
	}

	bc->cache.current_footprint += BLOB_HDR_LEN + size;

	return 0;
}

static int
lws_cache_blob_get(struct lws_cache_ttl_lru *_c, const char *specific_key,
		   const void **pdata, size_t *psize)
{
	lws_cache_blob_t *bc = (lws_cache_blob_t *)_c;
	struct lws_cache_ttl_lru *l1 = _c;
	uint8_t hdr[BLOB_HDR_LEN], *pay;
	char path[256], hex[41];
	size_t extant, ulen;
	lws_usec_t expiry;
	int fd;

	if (blob_hash_key(specific_key, hex))
		return 1;

	if (lws_diskcache_query(bc->lds, 0, hex, &fd, path, sizeof(path),
				&extant) != LWS_DISKCACHE_QUERY_EXISTS)
		return 1;

	if (blob_read(fd, hdr, sizeof(hdr)))
		goto bail;

	if (memcmp(hdr, blob_magic, sizeof(blob_magic)))
		goto bail; /* foreign or corrupt file, drop it */

	expiry = (lws_usec_t)lws_ser_ru64be(hdr + 4);
	ulen = (size_t)lws_ser_ru32be(hdr + 12);

	/* the file must be exactly the header plus the payload it claims */

	if (extant != BLOB_HDR_LEN + ulen)
		goto bail;

	/* an expired item is not usable... drop the file so the space back */

	if (expiry && expiry <= lws_now_usecs())
		goto bail;

	/* an item bigger than we would store today cannot be loaded */

	if (bc->cache.info.max_payload && ulen > bc->cache.info.max_payload)
		goto bail;

	/* caller only wanted to know if it exists */

	if (!pdata) {
		close(fd);

		return 0;
	}

	/*
	 * Fill the innermost (heap, L1) level with the payload and hand out
	 * a pointer into that, like the nscookiejar level does
	 */

	while (l1->child)
		l1 = l1->child;

	if (l1->info.ops->write(l1, specific_key, NULL, ulen, expiry,
				(void **)&pay))
		goto bail2;

	if (blob_read(fd, pay, ulen)) {
		l1->info.ops->invalidate(l1, specific_key);
		goto bail2;
	}

	close(fd);

	*pdata = pay;
	*psize = ulen;

	return 0;

bail:
	unlink(path);

bail2:
	close(fd);

	return 1;
}

static int
lws_cache_blob_invalidate(struct lws_cache_ttl_lru *_c, const char *wc_key)
{
	lws_cache_blob_t *bc = (lws_cache_blob_t *)_c;
	char path[256], hex[41];
	struct stat s;

	/* keys are hashed to filenames, so wildcards cannot be enumerated */

	if (strchr(wc_key, '*') || strchr(wc_key, '?'))
		return 0;

	if (blob_hash_key(wc_key, hex))
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%c/%c/%s",
		     bc->cache.info.u.blob.dir, hex[0], hex[1], hex);

	if (!stat(path, &s) && S_ISREG(s.st_mode) &&
	    bc->cache.current_footprint >= (uint64_t)s.st_size)
		bc->cache.current_footprint -= (uint64_t)s.st_size;

	unlink(path);

	return 0;
}

static int
lws_cache_blob_tag_match(struct lws_cache_ttl_lru *cache, const char *wc,
			 const char *tag, char lookup_rules)
{
	return lws_strcmp_wildcard(wc, strlen(wc), tag, strlen(tag));
}

/*
 * Item keys only exist on disk as hashes, so there is no way to enumerate the
 * keys matching a wildcard.  Always report no results.
 */

static int
lws_cache_blob_lookup(struct lws_cache_ttl_lru *_c, const char *wildcard_key,
		      lws_dll2_owner_t *results_owner)
{
	(void)_c;
	(void)wildcard_key;
	(void)results_owner;

	return 0;
}

#if defined(_DEBUG)
static void
lws_cache_blob_debug_dump(struct lws_cache_ttl_lru *_c)
{
#if (_LWS_ENABLED_LOGS & LLL_DEBUG)
	lws_cache_blob_t *bc = (lws_cache_blob_t *)_c;

	lwsl_cache("%s: %s at %s, approx %llu bytes\n", __func__,
		   bc->cache.info.name, bc->cache.info.u.blob.dir,
		   (unsigned long long)bc->cache.current_footprint);
#else
	(void)_c;
#endif
}
#endif

const struct lws_cache_ops lws_cache_ops_blob = {
	.create			= lws_cache_blob_create,
	.destroy		= lws_cache_blob_destroy,
	.expunge		= lws_cache_blob_expunge,

	.write			= lws_cache_blob_write,
	.tag_match		= lws_cache_blob_tag_match,
	.lookup			= lws_cache_blob_lookup,
	.invalidate		= lws_cache_blob_invalidate,
	.get			= lws_cache_blob_get,
#if defined(_DEBUG)
	.debug_dump		= lws_cache_blob_debug_dump,
#endif
};
