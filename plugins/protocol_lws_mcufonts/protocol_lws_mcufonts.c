/*
 * lws-mcufonts: serve mcufont faces a page at a time, made from .ttf files
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * These test plugins are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 *
 * Devices using lws_fonts_register_manifest() fetch fonts.json from us, then
 * <face>/<size>/<page>.mcufont beside it for each page of 256 codepoints
 * their text needs, at the size they want it.  The faces are each .ttf in a
 * directory, offered at any size from min-size to max-size.  We learn what's
 * in each face with the mcufont encoder's face_info at startup, and make a
 * page at a size with its rlefont_page only when a device first asks for it,
 * into an lws_diskcache that is kept trimmed to a size, so sizes that are no
 * longer asked for age out.  Until it's made we answer 404, and the device
 * sets that text in a face of its own and asks again later.
 *
 * See ./README.md
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

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * What the devices can take, from lib/misc/dlo/dlo-font-remote.c: we must
 * never list a face a device would have to truncate or refuse
 */
#define MCUF_DEV_NAME_MAX	63	/* chars in name[64] */
#define MCUF_DEV_PATH_MAX	63	/* chars in path[64] */
#define MCUF_DEV_PAGES_MAX	159	/* chars in pages[160] */
#define MCUF_DEV_RANGES_MAX	32
#define MCUF_DEV_MANIFEST_MAX	16384
#define MCUF_DEV_FACES_MAX	64
#define MCUF_PAGE_MAX		0x10ff	/* the page of U+10FFFF */
#define MCUF_SIZE_MIN		4	/* what the encoder can make */
#define MCUF_SIZE_MAX		255

#define MCUF_INFO_MAX		1024	/* face_info's stdout */
#define MCUF_QUEUE_MAX		64	/* jobs waiting their turn */

typedef struct mcuf_info {
	char			name[128];
	char			pages[512];
	unsigned int		height;
	unsigned int		units_per_em;
} mcuf_info_t;

static const lws_struct_map_t lsm_mcuf_info[] = {
	LSM_CARRAY	(mcuf_info_t, name,		"name"),
	LSM_CARRAY	(mcuf_info_t, pages,		"pages"),
	LSM_UNSIGNED	(mcuf_info_t, height,		"height"),
	LSM_UNSIGNED	(mcuf_info_t, units_per_em,	"units_per_em"),
};

static const lws_struct_map_t lsm_mcuf_info_schema[] = {
	LSM_SCHEMA	(mcuf_info_t, NULL, lsm_mcuf_info, "mcuf-info"),
};

/* a .ttf: a face we offer at any size from min-size to max-size */

typedef struct mcuf_face {
	lws_dll2_t		list;		/* vhd->faces */

	mcuf_info_t		info;
	uint16_t		ranges[MCUF_DEV_RANGES_MAX * 2];

	char			ttf[256];	/* its path */
	char			path[MCUF_DEV_PATH_MAX + 1]; /* in the url */
	char			id[128];	/* in the cache keys */

	int			nranges;
	uint8_t			state;		/* MCUF_FACE_ */
	uint8_t			listed;		/* in fonts.json */
} mcuf_face_t;

enum {
	MCUF_FACE_PENDING,
	MCUF_FACE_OK,
	MCUF_FACE_FAILED,
};

/* a run of the encoder, waiting for its turn or running */

typedef struct mcuf_job {
	lws_dll2_t		list;		/* vhd->queued or ->running */

	struct vhd		*vhd;
	mcuf_face_t		*face;
	struct lws_spawn_piped	*lsp;

	char			tmp[LWS_DISKCACHE_PATH_MAX];
	char			out[MCUF_INFO_MAX];
	size_t			olen;

	int			size;
	int			page;		/* -1: face_info */
	uint8_t			overflow;
} mcuf_job_t;

struct vhd {
	struct lws_context	*cx;
	struct lws_vhost	*vhost;
	struct lws_diskcache_scan *lds;

	lws_sorted_usec_list_t	sul_trim;
	lws_sorted_usec_list_t	sul_start;

	lws_dll2_owner_t	faces;
	lws_dll2_owner_t	queued;
	lws_dll2_owner_t	running;

	const char		*ttf_dir;
	const char		*cache_dir;
	const char		*encoder;

	char			*manifest;	/* fonts.json once all known */
	size_t			manifest_len;

	lws_usec_t		timeout_us;
	uint16_t		warm[MCUF_DEV_RANGES_MAX * 2];
	int			nwarm;		/* ranges of pages made at start */
	uint16_t		warm_sizes[MCUF_DEV_RANGES_MAX * 2];
	int			nwarm_sizes;	/* ...at these ranges of sizes */
	int			min_size;
	int			max_size;
	int			iterations;
	int			jobs_max;

	uint8_t			destroying;
	uint8_t			oom;
};

struct pss {
	size_t			pos;		/* into vhd->manifest */
	uint8_t			manifest;	/* we're sending it */
};

static const char *empty_env[] = { NULL };

static void
mcuf_start_cb(lws_sorted_usec_list_t *sul);
static void
mcuf_face_warm(struct vhd *vhd, mcuf_face_t *f);

/* four lowercase hex digits, and nothing else */

static int
mcuf_hex(const char *s, size_t len, uint32_t *v)
{
	size_t n;

	if (len != 4)
		return 1;

	*v = 0;
	for (n = 0; n < len; n++) {
		*v <<= 4;
		if (s[n] >= '0' && s[n] <= '9')
			*v |= (uint32_t)(s[n] - '0');
		else if (s[n] >= 'a' && s[n] <= 'f')
			*v |= (uint32_t)(s[n] - 'a' + 10);
		else
			return 1;
	}

	return 0;
}

/* a decimal from lo to hi, without leading zeros, and nothing else */

static int
mcuf_int(const char *s, size_t len, int lo, int hi, int *v)
{
	size_t n;

	if (!len || len > 7 || (len > 1 && *s == '0'))
		return 1;

	*v = 0;
	for (n = 0; n < len; n++) {
		if (s[n] < '0' || s[n] > '9')
			return 1;
		*v = (*v * 10) + (s[n] - '0');
	}

	return *v < lo || *v > hi;
}

/*
 * Runs of pages, like "0000-0005,0020", or with hex 0, of decimal sizes,
 * like "12-16,20", into first, last pairs, checked the same way the device
 * checks them.  Returns the count of pairs, or -1 if the list is bad, or
 * longer than a device can take
 */

static int
mcuf_runs(const char *list, int hex, int lo, int hi, uint16_t *ranges,
	  int max)
{
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	int n = 0, dash = 0, have = 0, i;
	uint32_t v;

	lws_tokenize_init(&ts, list, LWS_TOKENIZE_F_NO_INTEGERS |
				     LWS_TOKENIZE_F_NO_FLOATS);
	ts.len = strlen(list);

	do {
		e = lws_tokenize(&ts);
		switch (e) {
		case LWS_TOKZE_TOKEN:
			if (hex) {
				if (mcuf_hex(ts.token, ts.token_len, &v))
					return -1;
			} else {
				if (mcuf_int(ts.token, ts.token_len, 0, 0xffff,
					     &i))
					return -1;
				v = (uint32_t)i;
			}
			if (v < (uint32_t)lo || v > (uint32_t)hi)
				return -1;
			if (dash) {
				if (v < ranges[(n - 1) * 2])
					return -1;
				ranges[((n - 1) * 2) + 1] = (uint16_t)v;
				dash = 0;
				break;
			}
			if (have || n == max ||
			    (n && v <= ranges[((n - 1) * 2) + 1]))
				return -1;
			ranges[n * 2] = ranges[(n * 2) + 1] = (uint16_t)v;
			n++;
			have = 1;
			break;

		case LWS_TOKZE_DELIMITER:
			if (*ts.token == '-' && have && !dash) {
				dash = 1;
				break;
			}
			if (*ts.token == ',' && have && !dash) {
				have = 0;
				break;
			}
			return -1;

		case LWS_TOKZE_ENDED:
			break;

		default:
			return -1;
		}
	} while (e > 0);

	if (dash || !have)
		return -1;

	return n;
}

static int
mcuf_face_has_page(const mcuf_face_t *f, uint32_t page)
{
	int n;

	for (n = 0; n < f->nranges; n++)
		if (page >= f->ranges[n * 2] && page <= f->ranges[(n * 2) + 1])
			return 1;

	return 0;
}

/* only characters a device takes in a path, and that need no escaping */

static int
mcuf_name_ok(const char *s, size_t len)
{
	size_t n;

	if (!len || *s == '.')
		return 0;

	for (n = 0; n < len; n++)
		if (!((s[n] >= 'a' && s[n] <= 'z') ||
		      (s[n] >= 'A' && s[n] <= 'Z') ||
		      (s[n] >= '0' && s[n] <= '9') ||
		      s[n] == '.' || s[n] == '-' || s[n] == '_'))
			return 0;

	return 1;
}

/*
 * Cache objects are named by the sha1 of what they are made from, the ttf
 * identified by its path, file size and mtime, so a changed ttf is made
 * afresh
 */

static void
mcuf_key(const mcuf_face_t *f, int size, int page, int iterations,
	 char hex[41])
{
	static const char *hexchars = "0123456789abcdef";
	uint8_t digest[LWS_GENHASH_LARGEST];
	char k[sizeof(f->id) + 48];
	int n, m;

	if (page < 0)
		n = lws_snprintf(k, sizeof(k), "info:%s", f->id);
	else
		n = lws_snprintf(k, sizeof(k), "page:%s:%d:%04x:%d", f->id,
				 size, page, iterations);

	lws_SHA1((const unsigned char *)k, (size_t)n, digest);

	for (m = 0; m < 20; m++) {
		hex[m * 2] = hexchars[digest[m] >> 4];
		hex[(m * 2) + 1] = hexchars[digest[m] & 15];
	}
	hex[40] = '\0';
}

/*
 * face_info's output, from the encoder now or from the cache, into the face.
 * We check it's something every device can take before offering it.
 */

static int
mcuf_face_info_apply(struct vhd *vhd, mcuf_face_t *f, const char *buf,
		     size_t len)
{
	struct lejp_ctx jctx;
	lws_struct_args_t a;
	mcuf_info_t *i;
	int n;

	memset(&a, 0, sizeof(a));
	a.map_st[0] = lsm_mcuf_info_schema;
	a.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_mcuf_info_schema);
	a.ac_block_size = 1024;

	lws_struct_json_init_parse(&jctx, NULL, &a);
	n = lejp_parse(&jctx, (const uint8_t *)buf, (int)len);
	lejp_destruct(&jctx);
	if (n < 0 || !a.dest) {
		lwsac_free(&a.ac);
		goto bad;
	}

	i = (mcuf_info_t *)a.dest;
	f->info = *i;
	lwsac_free(&a.ac);

	/*
	 * Every size we offer must have a line height, that fits in 16 bits,
	 * as the device checks
	 */
	n = (int)strlen(f->info.name);
	if (n > MCUF_DEV_NAME_MAX || !f->info.height ||
	    f->info.height > 0xffff || !f->info.units_per_em ||
	    f->info.units_per_em > 0xffff ||
	    ((uint64_t)f->info.height * (unsigned int)vhd->min_size) +
		(f->info.units_per_em / 2) < f->info.units_per_em ||
	    ((uint64_t)f->info.height * (unsigned int)vhd->max_size) +
		(f->info.units_per_em / 2) >=
				(uint64_t)f->info.units_per_em * 0x10000 ||
	    strlen(f->info.pages) > MCUF_DEV_PAGES_MAX)
		goto bad;

	/* the name goes in our json as it is */
	while (n--)
		if (f->info.name[n] < ' ' || f->info.name[n] > '~' ||
		    f->info.name[n] == '"' || f->info.name[n] == '\\')
			goto bad;

	f->nranges = mcuf_runs(f->info.pages, 1, 0, MCUF_PAGE_MAX, f->ranges,
			       MCUF_DEV_RANGES_MAX);
	if (f->nranges <= 0)
		goto bad;

	f->state = MCUF_FACE_OK;
	mcuf_face_warm(vhd, f);

	return 0;

bad:
	lwsl_vhost_warn(vhd->vhost, "%s can't be offered", f->ttf);
	f->state = MCUF_FACE_FAILED;

	return 1;
}

/* the face_info we cached at an earlier start, if any */

static int
mcuf_face_info_cached(struct vhd *vhd, mcuf_face_t *f)
{
	char path[LWS_DISKCACHE_PATH_MAX], hex[41], buf[MCUF_INFO_MAX];
	size_t extant;
	ssize_t r;
	int fd;

	mcuf_key(f, 0, -1, 0, hex);
	if (lws_diskcache_query(vhd->lds, 1, hex, &fd, path, (int)sizeof(path),
				&extant) != LWS_DISKCACHE_QUERY_EXISTS)
		return 1;

	r = (extant && extant <= sizeof(buf)) ? read(fd, buf, extant) : -1;
	close(fd);
	if (r != (ssize_t)extant) {
		unlink(path);
		return 1;
	}

	return mcuf_face_info_apply(vhd, f, buf, extant);
}

static void
mcuf_face_info_cache(struct vhd *vhd, mcuf_face_t *f, const char *buf,
		     size_t len)
{
	char path[LWS_DISKCACHE_PATH_MAX], hex[41];
	size_t extant;
	int fd, ok;

	mcuf_key(f, 0, -1, 0, hex);
	switch (lws_diskcache_query(vhd->lds, 0, hex, &fd, path,
				    (int)sizeof(path), &extant)) {
	case LWS_DISKCACHE_QUERY_EXISTS:
		close(fd);
		return;
	case LWS_DISKCACHE_QUERY_CREATING:
		break;
	default:
		return;
	}

	ok = write(fd, buf, len) == (ssize_t)len;
	close(fd);
	if (!ok || lws_diskcache_finalize_name(path))
		unlink(path);
}

/*
 * Once every face is known, the manifest lists the ones we can offer.  It
 * never changes after that: a changed ttf dir is noticed at the next start.
 */

static void
mcuf_manifest_build(struct vhd *vhd)
{
	size_t alloc = MCUF_DEV_MANIFEST_MAX, pos = 0;
	unsigned int count = 0;
	const char *sep = "";
	char *m;

	if (vhd->manifest)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->faces)) {
		mcuf_face_t *f = lws_container_of(d, mcuf_face_t, list);

		if (f->state == MCUF_FACE_PENDING)
			return;
	} lws_end_foreach_dll(d);

	m = malloc(alloc);
	if (!m)
		return;

	pos = (size_t)lws_snprintf(m, alloc, "{\"fonts\":[");

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->faces)) {
		mcuf_face_t *f = lws_container_of(d, mcuf_face_t, list);
		char e[384];
		int n;

		if (f->state != MCUF_FACE_OK)
			continue;

		n = lws_snprintf(e, sizeof(e), "%s\n {\"name\":\"%s\",\"path\":"
				 "\"%s\",\"sizes\":\"%d-%d\",\"height\":%u,"
				 "\"units_per_em\":%u,\"pages\":\"%s\"}",
				 sep, f->info.name, f->path, vhd->min_size,
				 vhd->max_size, f->info.height,
				 f->info.units_per_em, f->info.pages);

		/* leave room for the end */
		if (count == MCUF_DEV_FACES_MAX || n >= (int)sizeof(e) - 1 ||
		    pos + (size_t)n + 4 >= alloc) {
			lwsl_vhost_warn(vhd->vhost, "fonts.json is full, "
					"leaving out %s", f->path);
			continue;
		}

		memcpy(m + pos, e, (size_t)n);
		pos += (size_t)n;
		sep = ",";
		count++;
		f->listed = 1;
	} lws_end_foreach_dll(d);

	pos += (size_t)lws_snprintf(m + pos, alloc - pos, "\n]}\n");

	vhd->manifest = m;
	vhd->manifest_len = pos;

	lwsl_vhost_notice(vhd->vhost, "fonts.json ready, %u faces", count);
}

static mcuf_job_t *
mcuf_job_find(lws_dll2_owner_t *o, const mcuf_face_t *f, int size, int page)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(o)) {
		mcuf_job_t *j = lws_container_of(d, mcuf_job_t, list);

		if (j->face == f && j->size == size && j->page == page)
			return j;
	} lws_end_foreach_dll(d);

	return NULL;
}

/* force: the queue's limit is for what devices ask for, not what we warm */

static int
mcuf_job_queue(struct vhd *vhd, mcuf_face_t *f, int size, int page, int force)
{
	mcuf_job_t *j;

	if (mcuf_job_find(&vhd->queued, f, size, page) ||
	    mcuf_job_find(&vhd->running, f, size, page))
		return 0;

	if (!force && vhd->queued.count >= MCUF_QUEUE_MAX)
		return 1;

	j = malloc(sizeof(*j));
	if (!j)
		return 1;

	memset(j, 0, sizeof(*j));
	j->vhd = vhd;
	j->face = f;
	j->size = size;
	j->page = page;

	lws_dll2_add_tail(&j->list, &vhd->queued);

	if (!vhd->destroying)
		lws_sul_schedule(vhd->cx, 0, &vhd->sul_start, mcuf_start_cb, 1);

	return 0;
}

/* the warm-pages a face has, that aren't made yet at size, are made now */

static int
mcuf_face_warm_size(struct vhd *vhd, mcuf_face_t *f, int size)
{
	char path[LWS_DISKCACHE_PATH_MAX], hex[41];
	size_t extant;
	int n, fd;
	uint32_t p;

	for (n = 0; n < vhd->nwarm; n++)
		for (p = vhd->warm[n * 2]; p <= vhd->warm[(n * 2) + 1]; p++) {
			if (!mcuf_face_has_page(f, p))
				continue;
			mcuf_key(f, size, (int)p, vhd->iterations, hex);
			if (lws_diskcache_query(vhd->lds, 1, hex, &fd, path,
						(int)sizeof(path), &extant) ==
						LWS_DISKCACHE_QUERY_EXISTS) {
				close(fd);
				continue;
			}
			if (mcuf_job_queue(vhd, f, size, (int)p, 1))
				return 1;
		}

	return 0;
}

static void
mcuf_face_warm(struct vhd *vhd, mcuf_face_t *f)
{
	int n, z;

	for (n = 0; n < vhd->nwarm_sizes; n++)
		for (z = vhd->warm_sizes[n * 2];
		     z <= vhd->warm_sizes[(n * 2) + 1]; z++)
			if (mcuf_face_warm_size(vhd, f, z))
				return;
}

static void
mcuf_job_free(mcuf_job_t *j)
{
	lws_dll2_remove(&j->list);
	free(j);
}

static void
mcuf_reap_cb(void *opaque, const lws_spawn_resource_us_t *res, siginfo_t *si,
	     int we_killed_him)
{
	mcuf_job_t *j = (mcuf_job_t *)opaque;
	struct vhd *vhd = j->vhd;
	mcuf_face_t *f = j->face;
	struct stat s;
	int ok;

	(void)res;

	/* lws reports a clean exit as code 1, see lws_spawn_note_reaped() */
	ok = !we_killed_him && si->si_code == 1 && !si->si_status;

	if (j->page < 0) {
		if (!ok || j->overflow) {
			lwsl_vhost_warn(vhd->vhost, "face_info %s failed (%d)",
					f->ttf, si->si_status);
			f->state = MCUF_FACE_FAILED;
		} else if (!mcuf_face_info_apply(vhd, f, j->out, j->olen))
			mcuf_face_info_cache(vhd, f, j->out, j->olen);

		mcuf_manifest_build(vhd);
	} else {
		if (ok && !stat(j->tmp, &s) && s.st_size > 0 &&
		    !lws_diskcache_finalize_name(j->tmp))
			lwsl_vhost_info(vhd->vhost, "made %s/%d/%04x.mcufont",
					f->path, j->size, j->page);
		else {
			lwsl_vhost_warn(vhd->vhost, "making %s/%d/%04x.mcufont "
					"failed (%d%s)", f->path, j->size,
					j->page, si->si_status,
					we_killed_him ? ", timed out" : "");
			unlink(j->tmp);
		}
	}

	mcuf_job_free(j);

	if (!vhd->destroying)
		lws_sul_schedule(vhd->cx, 0, &vhd->sul_start, mcuf_start_cb, 1);
}

static int
mcuf_job_start(struct vhd *vhd, mcuf_job_t *j)
{
	struct lws_spawn_piped_info info;
	char size[8], page[8], iters[8], hex[41];
	const char *ea[8];
	size_t extant;
	int fd, n = 0;

	ea[n++] = vhd->encoder;
	if (j->page < 0) {
		ea[n++] = "face_info";
		ea[n++] = j->face->ttf;
	} else {
		/* the encoder writes the page into a temp object of the cache */

		mcuf_key(j->face, j->size, j->page, vhd->iterations, hex);
		switch (lws_diskcache_query(vhd->lds, 0, hex, &fd, j->tmp,
					    (int)sizeof(j->tmp), &extant)) {
		case LWS_DISKCACHE_QUERY_CREATING:
			close(fd);
			break;
		case LWS_DISKCACHE_QUERY_EXISTS:
			close(fd);
			/* fallthru */
		default:
			return 1;
		}

		lws_snprintf(size, sizeof(size), "%d", j->size);
		lws_snprintf(page, sizeof(page), "%04x", j->page);
		lws_snprintf(iters, sizeof(iters), "%d", vhd->iterations);

		ea[n++] = "rlefont_page";
		ea[n++] = j->face->ttf;
		ea[n++] = size;
		ea[n++] = page;
		ea[n++] = j->tmp;
		ea[n++] = iters;
	}
	ea[n] = NULL;

	memset(&info, 0, sizeof(info));
	info.vh			= vhd->vhost;
	info.exec_array		= ea;
	info.env_array		= empty_env;
	info.protocol_name	= "lws-mcufonts-stdwsi";
	info.timeout_us		= vhd->timeout_us;
	info.reap_cb		= mcuf_reap_cb;
	info.opaque		= j;
	info.plsp		= &j->lsp;

	lws_dll2_remove(&j->list);
	lws_dll2_add_tail(&j->list, &vhd->running);

	if (!lws_spawn_piped(&info)) {
		lwsl_vhost_err(vhd->vhost, "unable to spawn %s", vhd->encoder);
		if (j->page >= 0)
			unlink(j->tmp);
		return 1;
	}

	return 0;
}

static void
mcuf_start_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_start);

	while (vhd->queued.count && (int)vhd->running.count < vhd->jobs_max) {
		mcuf_job_t *j = lws_container_of(lws_dll2_get_head(&vhd->queued),
						 mcuf_job_t, list);

		if (!mcuf_job_start(vhd, j))
			continue;

		if (j->page < 0) {
			j->face->state = MCUF_FACE_FAILED;
			mcuf_job_free(j);
			mcuf_manifest_build(vhd);
		} else
			mcuf_job_free(j);
	}
}

static void
mcuf_trim_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_trim);
	int secs;

	lws_diskcache_trim(vhd->lds);
	secs = lws_diskcache_secs_to_idle(vhd->lds);

	lws_sul_schedule(vhd->cx, 0, &vhd->sul_trim, mcuf_trim_cb,
			 (secs > 0 ? secs : 1) * LWS_US_PER_SEC);
}

static int
mcuf_face_cmp(const lws_dll2_t *a, const lws_dll2_t *b)
{
	const mcuf_face_t *fa = lws_container_of(a, mcuf_face_t, list),
			  *fb = lws_container_of(b, mcuf_face_t, list);

	return strcmp(fa->path, fb->path);
}

/* each .ttf in the dir is a face */

static int
mcuf_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	size_t len = strlen(lde->name);
	mcuf_face_t *f;
	struct stat s;
	char ttf[256];

	if ((lde->type != LDOT_FILE && lde->type != LDOT_UNKNOWN) || len < 5 ||
	    (strcmp(lde->name + len - 4, ".ttf") &&
	     strcmp(lde->name + len - 4, ".otf")))
		return 0;

	len -= 4;
	if (!mcuf_name_ok(lde->name, len) || len > MCUF_DEV_PATH_MAX ||
	    lws_snprintf(ttf, sizeof(ttf), "%s/%s", dirpath, lde->name) >=
							(int)sizeof(ttf) ||
	    stat(ttf, &s) || !S_ISREG(s.st_mode)) {
		lwsl_vhost_warn(vhd->vhost, "ignoring %s", lde->name);
		return 0;
	}

	f = malloc(sizeof(*f));
	if (!f) {
		vhd->oom = 1;
		return 1;
	}
	memset(f, 0, sizeof(*f));

	lws_strncpy(f->ttf, ttf, sizeof(f->ttf));
	lws_strncpy(f->path, lde->name, len + 1);
	/* the path fits, so this always does */
	lws_snprintf(f->id, sizeof(f->id), "%s:%llu:%llu", f->path,
		     (unsigned long long)s.st_size,
		     (unsigned long long)s.st_mtime);

	lws_dll2_add_sorted(&f->list, &vhd->faces, mcuf_face_cmp);

	return 0;
}

static int
mcuf_pvo_int(void *in, const char *name, int def, int lo, int hi, int *v)
{
	const char *s;

	*v = def;
	if (lws_pvo_get_str(in, name, &s))
		return 0;

	return mcuf_int(s, strlen(s), lo, hi, v);
}

static int
mcuf_init(struct vhd *vhd, void *in)
{
	const char *warm;
	uid_t uid;
	gid_t gid;
	int mb, t;

	if (lws_pvo_get_str(in, "cache-dir", &vhd->cache_dir) ||
	    lws_pvo_get_str(in, "encoder", &vhd->encoder)) {
		lwsl_vhost_err(vhd->vhost, "needs ttf-dir, cache-dir and "
			       "encoder pvos");
		return 1;
	}

	if (mcuf_pvo_int(in, "min-size", 6, MCUF_SIZE_MIN, MCUF_SIZE_MAX,
			 &vhd->min_size) ||
	    mcuf_pvo_int(in, "max-size", 100, vhd->min_size, MCUF_SIZE_MAX,
			 &vhd->max_size) ||
	    mcuf_pvo_int(in, "cache-size-mb", 64, 1, 1 << 20, &mb) ||
	    mcuf_pvo_int(in, "iterations", 10, 0, 1000, &vhd->iterations) ||
	    mcuf_pvo_int(in, "jobs", 2, 1, 64, &vhd->jobs_max) ||
	    mcuf_pvo_int(in, "job-timeout-s", 600, 1, 86400, &t)) {
		lwsl_vhost_err(vhd->vhost, "bad min-size, max-size, "
			       "cache-size-mb, iterations, jobs or "
			       "job-timeout-s");
		return 1;
	}
	vhd->timeout_us = (lws_usec_t)t * LWS_US_PER_SEC;

	if (!lws_pvo_get_str(in, "warm-pages", &warm)) {
		vhd->nwarm = mcuf_runs(warm, 1, 0, MCUF_PAGE_MAX, vhd->warm,
				       MCUF_DEV_RANGES_MAX);
		if (vhd->nwarm <= 0) {
			lwsl_vhost_err(vhd->vhost, "bad warm-pages");
			return 1;
		}
	}

	if (!lws_pvo_get_str(in, "warm-sizes", &warm)) {
		vhd->nwarm_sizes = mcuf_runs(warm, 0, vhd->min_size,
					     vhd->max_size, vhd->warm_sizes,
					     MCUF_DEV_RANGES_MAX);
		if (vhd->nwarm_sizes <= 0) {
			lwsl_vhost_err(vhd->vhost, "bad warm-sizes");
			return 1;
		}
	}

	/*
	 * The dirs belong to whoever we will be once privileges are dropped,
	 * or to us, if we aren't going to drop any
	 */
	lws_get_effective_uid_gid(vhd->cx, &uid, &gid);
	if (!uid)
		uid = getuid();
	if (lws_diskcache_prepare(vhd->cache_dir, 0700, uid)) {
		lwsl_vhost_err(vhd->vhost, "can't prepare %s", vhd->cache_dir);
		return 1;
	}

	vhd->lds = lws_diskcache_create(vhd->cache_dir,
					(uint64_t)mb * 1024 * 1024);
	if (!vhd->lds)
		return 1;

	/* lws_dir() doesn't tell us if it could open the dir */
	lws_dir(vhd->ttf_dir, vhd, mcuf_dir_cb);
	if (vhd->oom)
		return 1;
	if (!vhd->faces.count) {
		lwsl_vhost_err(vhd->vhost, "no usable .ttf in %s", vhd->ttf_dir);
		return 1;
	}

	/*
	 * What each face has, from the cache if we've seen this ttf before, or
	 * else from face_info.  The jobs only start from the event loop, once
	 * lwsws has dropped its privileges
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->faces)) {
		mcuf_face_t *f = lws_container_of(d, mcuf_face_t, list);

		if (mcuf_face_info_cached(vhd, f) &&
		    f->state == MCUF_FACE_PENDING) {
			/* an info job per face, so never limited by the queue */
			mcuf_job_t *j = malloc(sizeof(*j));

			if (!j)
				return 1;
			memset(j, 0, sizeof(*j));
			j->vhd = vhd;
			j->face = f;
			j->page = -1;
			lws_dll2_add_tail(&j->list, &vhd->queued);
		}
	} lws_end_foreach_dll(d);

	lwsl_vhost_notice(vhd->vhost, "%u faces from %s, learning %u",
			  (unsigned int)vhd->faces.count, vhd->ttf_dir,
			  (unsigned int)vhd->queued.count);

	mcuf_manifest_build(vhd);

	lws_sul_schedule(vhd->cx, 0, &vhd->sul_start, mcuf_start_cb, 1);
	lws_sul_schedule(vhd->cx, 0, &vhd->sul_trim, mcuf_trim_cb,
			 LWS_US_PER_SEC);

	return 0;
}

static void
mcuf_destroy(struct vhd *vhd)
{
	vhd->destroying = 1;
	lws_sul_cancel(&vhd->sul_start);
	lws_sul_cancel(&vhd->sul_trim);

	/* let go of running jobs without their reap: lws ends the children */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->running)) {
		mcuf_job_t *j = lws_container_of(d, mcuf_job_t, list);

		lws_spawn_piped_destroy(&j->lsp);
		if (j->page >= 0)
			unlink(j->tmp);
		mcuf_job_free(j);
	} lws_end_foreach_dll_safe(d, d1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->queued)) {
		mcuf_job_free(lws_container_of(d, mcuf_job_t, list));
	} lws_end_foreach_dll_safe(d, d1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->faces)) {
		mcuf_face_t *f = lws_container_of(d, mcuf_face_t, list);

		lws_dll2_remove(&f->list);
		free(f);
	} lws_end_foreach_dll_safe(d, d1);

	free(vhd->manifest);
	vhd->manifest = NULL;

	lws_diskcache_destroy(&vhd->lds);
}

/*
 * A page url is <face path>/<size>/<4 lowercase hex>.mcufont, the face one
 * fonts.json lists, the size, in decimal without leading zeros, one from
 * min-size to max-size, and the page one the face has: nothing else gets
 * near the cache or a job
 */

static mcuf_face_t *
mcuf_page_url(struct vhd *vhd, const char *url, int *size, uint32_t *page)
{
	const char *sl = strchr(url, '/'), *sl2;
	size_t fl;

	if (!sl)
		return NULL;
	sl2 = strchr(sl + 1, '/');
	if (!sl2 || mcuf_int(sl + 1, lws_ptr_diff_size_t(sl2, sl + 1),
			     vhd->min_size, vhd->max_size, size) ||
	    strlen(sl2) != 13 || strcmp(sl2 + 5, ".mcufont") ||
	    mcuf_hex(sl2 + 1, 4, page) || *page > MCUF_PAGE_MAX)
		return NULL;

	fl = lws_ptr_diff_size_t(sl, url);

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->faces)) {
		mcuf_face_t *f = lws_container_of(d, mcuf_face_t, list);

		if (f->listed && strlen(f->path) == fl &&
		    !strncmp(f->path, url, fl))
			return mcuf_face_has_page(f, *page) ? f : NULL;
	} lws_end_foreach_dll(d);

	return NULL;
}

static int
mcuf_http(struct lws *wsi, struct vhd *vhd, struct pss *pss, const char *url)
{
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	char path[LWS_DISKCACHE_PATH_MAX], hex[41];
	mcuf_face_t *f;
	uint32_t page;
	size_t extant;
	int fd, n, size;

	/* the url is relative to our mount, with or without its leading / */
	if (*url == '/')
		url++;

	if (!strcmp(url, "fonts.json")) {
		if (!vhd->manifest)
			goto bail_404; /* the device asks again later */

		pss->pos = 0;
		pss->manifest = 1;
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"application/json",
						vhd->manifest_len, &p, end) ||
		    lws_add_http_header_by_name(wsi,
				(const unsigned char *)"cache-control:",
				(const unsigned char *)"no-cache", 8, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		lws_callback_on_writable(wsi);

		return 0;
	}

	f = mcuf_page_url(vhd, url, &size, &page);
	if (!f)
		goto bail_404;

	mcuf_key(f, size, (int)page, vhd->iterations, hex);
	if (lws_diskcache_query(vhd->lds, 1, hex, &fd, path, (int)sizeof(path),
				&extant) == LWS_DISKCACHE_QUERY_EXISTS) {
		close(fd);

		n = lws_serve_http_file(wsi, path, "application/octet-stream",
					NULL, 0);
		if (n < 0 || (n > 0 && lws_http_transaction_completed(wsi)))
			return -1;

		return 0;
	}

	if (mcuf_job_queue(vhd, f, size, (int)page, 0))
		lwsl_vhost_notice(vhd->vhost, "too busy to make %s", url);

bail_404:
	if (lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL))
		return -1;

	return lws_http_transaction_completed(wsi);
}

static int
callback_lws_mcufonts(struct lws *wsi, enum lws_callback_reasons reason,
		      void *user, void *in, size_t len)
{
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(
				lws_get_vhost(wsi), lws_get_protocol(wsi));
	uint8_t buf[LWS_PRE + 2048];
	struct pss *pss = (struct pss *)user;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
			return 0;

		/* we only serve on vhosts that tell us where the ttfs are */
		if (!in || !lws_pvo_search((const struct lws_protocol_vhost_options *)in,
					   "ttf-dir"))
			return 0;

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
						  sizeof(struct vhd));
		if (!vhd)
			return -1;

		vhd->cx = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		lws_pvo_get_str(in, "ttf-dir", &vhd->ttf_dir);

		if (mcuf_init(vhd, in)) {
			mcuf_destroy(vhd);
			return -1;
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd)
			mcuf_destroy(vhd);
		break;

	case LWS_CALLBACK_HTTP:
		if (!vhd) {
			if (lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND,
						   NULL))
				return -1;
			return lws_http_transaction_completed(wsi);
		}

		return mcuf_http(wsi, vhd, pss, (const char *)in);

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!vhd || !pss->manifest || pss->pos >= vhd->manifest_len)
			break;

		n = vhd->manifest_len - pss->pos;
		if (n > sizeof(buf) - LWS_PRE)
			n = sizeof(buf) - LWS_PRE;
		memcpy(buf + LWS_PRE, vhd->manifest + pss->pos, n);
		pss->pos += n;

		if (lws_write(wsi, buf + LWS_PRE, n,
			      pss->pos == vhd->manifest_len ?
				LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP) != (int)n)
			return 1;

		if (pss->pos == vhd->manifest_len) {
			pss->manifest = 0;
			return lws_http_transaction_completed(wsi);
		}

		lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the encoder's stdin, stdout and stderr */

static int
callback_lws_mcufonts_stdwsi(struct lws *wsi, enum lws_callback_reasons reason,
			     void *user, void *in, size_t len)
{
	mcuf_job_t *j = (mcuf_job_t *)lws_get_opaque_user_data(wsi);
	char buf[256];
	ssize_t r;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX_FILE:
		r = read((int)(intptr_t)lws_get_socket_fd(wsi), buf,
			 sizeof(buf));
		if (r < 1)
			return -1;
		if (!j)
			break;

		if (lws_spawn_get_stdfd(wsi) == 2) {
			lwsl_vhost_info(j->vhd->vhost, "encoder: %.*s", (int)r,
					buf);
			break;
		}

		/* only face_info's stdout is any use to us */
		if (j->page >= 0 || lws_spawn_get_stdfd(wsi) != 1)
			break;

		n = (size_t)r;
		if (j->olen + n > sizeof(j->out)) {
			j->overflow = 1;
			break;
		}
		memcpy(j->out + j->olen, buf, n);
		j->olen += n;
		break;

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		/* the spawn must hear, or it never collects the child */
		if (j)
			lws_spawn_stdwsi_closed(j->lsp, wsi);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_MCUFONTS \
	{ \
		"lws-mcufonts", \
		callback_lws_mcufonts, \
		sizeof(struct pss), \
		0, 0, NULL, 0 \
	}, { \
		"lws-mcufonts-stdwsi", \
		callback_lws_mcufonts_stdwsi, \
		0, 0, 0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols lws_mcufonts_protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_MCUFONTS
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t lws_mcufonts = {
	.hdr = {
		.name = "lws mcufonts",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = lws_mcufonts_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_mcufonts_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
