/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
 */

#if !defined(NO_GNU_SOURCE_THIS_TIME)
#define NO_GNU_SOURCE_THIS_TIME
#endif
#if !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#include "private-lib-core.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#if defined(WIN32)
#include <direct.h>
#define read _read
#define open _open
#define close _close
#define write _write
#define mkdir(x,y) _mkdir(x)
#define rmdir _rmdir
#define unlink _unlink
#define HAVE_STRUCT_TIMESPEC
#if defined(pid_t)
#undef pid_t
#endif
#endif /* win32 */

#if !defined(LWS_PLAT_FREERTOS)

#if defined(WIN32)
#include "../../win32port/dirent/dirent-win32.h"
#else
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#endif

static int filter(const struct dirent *ent)
{
	if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
		return 0;

	return 1;
}


#if !defined(WIN32)
static char csep = '/';
#else
static char csep = '\\';
#endif

/*
 * dirpath + separator + name, allocated to fit.  The callers act on the
 * result (stat, recurse, unlink, rmdir), so it must never be a truncated
 * prefix that names something else: there is no fixed-size buffer here to
 * truncate into, the OS judges whether the length is usable.
 */
static char *
lws_dir_compose(const char *dirpath, const char *name)
{
	size_t ld = strlen(dirpath), ln = strlen(name);
	char *p = lws_malloc(ld + ln + 2, __func__);

	if (!p)
		return NULL;

	memcpy(p, dirpath, ld);
	p[ld] = csep;
	memcpy(p + ld + 1, name, ln + 1);

	return p;
}

static void
lws_dir_via_stat(const char *dirpath, const char *name,
		 struct lws_dir_entry *lde)
{
	struct stat s;
	char *combo;

	lde->type = LDOT_UNKNOWN;

	combo = lws_dir_compose(dirpath, name);
	if (!combo)
		return;

	/*
	 * This is the fallback for filesystems that don't fill in d_type (XFS
	 * with ftype=0, ZFS) and for platforms that never do.  It must agree
	 * with what the d_type path reports, ie, a symlink must come out as
	 * LDOT_LINK and not as whatever it points at... stat() follows the
	 * link and would report a symlink-to-dir as LDOT_DIR, letting rm -rf
	 * style callbacks recurse out of the tree they are walking.
	 */

#if defined(WIN32) || defined(_WIN32)
	if (!stat(combo, &s)) {
#else
	if (!lstat(combo, &s)) {
#endif
		switch (s.st_mode & S_IFMT) {
		case S_IFBLK:
			lde->type = LDOT_BLOCK;
			break;
		case S_IFCHR:
			lde->type = LDOT_CHAR;
			break;
		case S_IFDIR:
			lde->type = LDOT_DIR;
			break;
		case S_IFIFO:
			lde->type = LDOT_FIFO;
			break;
#if !defined(WIN32)
		case S_IFLNK:
			lde->type = LDOT_LINK;
			break;
#endif
		case S_IFREG:
			lde->type = LDOT_FILE;
			break;
		default:
			break;
		}
	}

	lws_free(combo);
}

static void
_fill_lde(const char *dirpath, const char *name, unsigned int type,
	  struct lws_dir_entry *lde)
{
	lde->name = name;

	/*
	 * some filesystems don't report this (ZFS) and tell that
	 * files are LDOT_UNKNOWN
	 */

#if defined(__sun) || defined(__QNX__)
	lws_dir_via_stat(dirpath, name, lde);
#else
	/*
	 * XFS on Linux doesn't fill in d_type at all, always zero.
	 */

	     if (DT_BLK  != DT_UNKNOWN && type == DT_BLK)
		lde->type = LDOT_BLOCK;
	else if (DT_CHR  != DT_UNKNOWN && type == DT_CHR)
		lde->type = LDOT_CHAR;
	else if (DT_DIR  != DT_UNKNOWN && type == DT_DIR)
		lde->type = LDOT_DIR;
	else if (DT_FIFO != DT_UNKNOWN && type == DT_FIFO)
		lde->type = LDOT_FIFO;
	else if (DT_LNK  != DT_UNKNOWN && type == DT_LNK)
		lde->type = LDOT_LINK;
	else if (DT_REG  != DT_UNKNOWN && type == DT_REG)
		lde->type = LDOT_FILE;
	else if (DT_SOCK != DT_UNKNOWN && type == DT_SOCK)
		lde->type = LDOTT_SOCKET;
	else {
		lde->type = LDOT_UNKNOWN;
		lws_dir_via_stat(dirpath, name, lde);
	}
#endif
}

int
lws_dir_via_info(struct lws_dir_info *info)
{
	struct dirent **namelist = NULL;
	struct lws_dir_entry lde;
	unsigned int type = 0;
	int n, i, ret = 1;

	assert(info->dirpath);
	assert(info->cb);

	n = scandir((char *)info->dirpath, &namelist, filter, alphasort);
	if (n < 0) {
		lwsl_info("Scandir on '%s' failed, errno %d\n", info->dirpath, LWS_ERRNO);
		return 1;
	}

	for (i = 0; i < n; i++) {
#if !defined(__sun) && !defined(__QNX__)
		type = namelist[i]->d_type;
#endif
		if ((char *)strchr(namelist[i]->d_name, '~'))
			goto skip;

		_fill_lde(info->dirpath, namelist[i]->d_name, type, &lde);

		if (info->cb(info->dirpath, info->user, &lde)) {
			while (i < n)
				free(namelist[i++]);
			ret = 0; /* told to stop by cb */
			goto bail;
		}
skip:
		free(namelist[i]);
	}

	if (info->do_toplevel_cb) {
		lde.name = "";
		lws_dir_via_stat(info->dirpath, "", &lde);

		if (info->cb(info->dirpath, info->user, &lde))
			ret = 0; /* told to stop by cb */
	}

bail:
	free(namelist);

	return ret;
}

int
lws_dir(const char *dirpath, void *user, lws_dir_callback_function cb)
{
	struct lws_dir_info info;

	memset(&info, 0, sizeof(info));

	info.dirpath = dirpath;
	info.user = user;
	info.cb = cb;

	return lws_dir_via_info(&info);
}

/*
 * Check filename against one globby filter
 *
 * We can support things like "*.rpm"
 */

static int
lws_dir_glob_check(const char *nm, const char *filt)
{
	while (*nm) {
		if (*filt == '*') {
			if (!strcmp(nm, filt + 1))
				return 1;
		} else {
			if (*nm != *filt)
				return 0;
			filt++;
		}
		nm++;
	}

	return 0;
}

int
lws_dir_du_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	lws_dir_du_t *du = (lws_dir_du_t *)user;
	struct stat s;
	char *path;

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	path = lws_dir_compose(dirpath, lde->name);
	if (!path)
		return 1;

	if (lde->type == LDOT_DIR) {
		lws_dir(path, user, lws_dir_du_cb);
		lws_free(path);

		return 0;
	}

	if (lde->type == LDOT_FILE) {
		if (stat(path, &s))
			lwsl_warn("%s: stat %s failed %d\n", __func__,
				  path, errno);
		else {
			du->size_in_bytes += (uint64_t)s.st_size;
			du->count_files++;
		}
	}

	lws_free(path);

	return 0;
}

/*
 * We get passed a single filter string, like "*.txt" or "mydir/\*.rpm" or so.
 */

int
lws_dir_glob_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	lws_dir_glob_t *filter = (lws_dir_glob_t*)user;
	char *path;

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	if (lde->type == LDOT_DIR)
		return 0;

	if (lws_dir_glob_check(lde->name, filter->filter)) {
		path = lws_dir_compose(dirpath, lde->name);
		if (!path)
			return 1;
		filter->cb(filter->user, path);
		lws_free(path);
	}

	return 0;
}

/*
 * How deep below the starting dir rm -rf will go.  The walk never composes
 * a path that could be truncated, so it always makes progress; this keeps
 * the stack (and, on the descriptor walk, the open directory fds) it can
 * take bounded.  A subtree deeper than this is left in place and logged.
 */
#define LWS_DIR_RM_RF_MAX_DEPTH 64

#if !defined(WIN32) && !defined(_WIN32) && defined(O_DIRECTORY) && \
    defined(O_NOFOLLOW) && defined(AT_REMOVEDIR) && \
    defined(AT_SYMLINK_NOFOLLOW)
/*
 * rm -rf walks relative to directory fds wherever the platform has the
 * *at() calls (Linux, the BSDs, OSX, ...).  Each directory is opened with
 * O_NOFOLLOW from an fd on its parent and emptied through its own fd, so no
 * path is ever re-resolved: a directory swapped for a symlink to somewhere
 * else between our look at it and our use of it makes the open fail rather
 * than taking us out of the tree, and everything we remove is named
 * relative to a directory we hold open inside it.
 *
 * Platforms without them (windows, which also has no O_NOFOLLOW, and any
 * other without openat()) keep the walk by path below, which refuses links
 * it can see but can't close the race against one appearing afterwards.
 */
#define LWS_DIR_RM_RF_AT

#if !defined(O_CLOEXEC)
#define O_CLOEXEC 0
#endif

static int
lws_dir_rm_rf_fd(int fd, int depth);

/*
 * Remove name, relative to the open directory dfd, with everything below it.
 * Returns 0 if it is gone.
 */

static int
lws_dir_rm_rf_at(int dfd, const char *name, int depth)
{
	struct stat st;
	int fd;

	if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW))
		return errno != ENOENT;

	if (!S_ISDIR(st.st_mode)) {
		/*
		 * Files, and symlinks wherever they point: unlinkat() removes
		 * the link itself, it never follows it
		 */
		if (unlinkat(dfd, name, 0)) {
			lwsl_warn("%s: unlink %s failed %d\n", __func__, name,
				  errno);
			return 1;
		}

		return 0;
	}

	if (depth >= LWS_DIR_RM_RF_MAX_DEPTH) {
		lwsl_warn("%s: depth limit, leaving %s\n", __func__, name);

		return 1;
	}

	fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
			       O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		/*
		 * O_NOFOLLOW on a symlink is ELOOP on Linux and OSX, EMLINK on
		 * FreeBSD and EFTYPE on NetBSD
		 */
		if (errno != ELOOP && errno != ENOTDIR && errno != EMLINK
#if defined(EFTYPE)
		    && errno != EFTYPE
#endif
		) {
			lwsl_warn("%s: open %s failed %d\n", __func__, name,
				  errno);
			return 1;
		}

		/*
		 * It was swapped for a symlink or a file since the fstatat():
		 * we refused to follow it, now remove it like any other link.
		 * If it was swapped back to a dir meanwhile this fails and we
		 * leave it, rather than chase it.
		 */
		if (unlinkat(dfd, name, 0)) {
			lwsl_warn("%s: unlink %s failed %d\n", __func__, name,
				  errno);
			return 1;
		}

		return 0;
	}

	if (lws_dir_rm_rf_fd(fd, depth + 1))
		return 1; /* something below stays, already logged */

	if (unlinkat(dfd, name, AT_REMOVEDIR)) {
		lwsl_warn("%s: rmdir %s failed %d\n", __func__, name, errno);
		return 1;
	}

	return 0;
}

/*
 * Empty the directory open on fd, taking ownership of fd.  Returns nonzero
 * if something in it could not be removed.
 */

static int
lws_dir_rm_rf_fd(int fd, int depth)
{
	int pass, removed, failed = 0;
	struct dirent *de;
	DIR *d;

	d = fdopendir(fd);
	if (!d) {
		lwsl_warn("%s: fdopendir failed %d\n", __func__, errno);
		close(fd);
		return 1;
	}

	/*
	 * Whether readdir() still reports every remaining entry after others
	 * were removed under it is unspecified (some filesystems skip some),
	 * so take another pass while the last one removed anything.  It is
	 * bounded so something refilling the dir as fast as we empty it can't
	 * keep us here.
	 */

	for (pass = 0; pass < 8; pass++) {
		removed = failed = 0;
		while ((de = readdir(d))) {
			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;
			if (lws_dir_rm_rf_at(fd, de->d_name, depth))
				failed = 1;
			else
				removed = 1;
		}
		if (!removed)
			break;
		rewinddir(d);
	}

	closedir(d); /* closes fd */

	return failed;
}

int
lws_dir_rm_rf_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	int dfd;

	/* user is documented as ignored */

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	/*
	 * The starting dir must itself be a directory, not a symlink to one:
	 * it may be a name that someone else can replace (eg, an hls media
	 * subdir).  lws_dir() listed it by path, but the names it gives us
	 * are only ever acted on relative to what we open here.
	 */

	dfd = open(dirpath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC |
			    O_NONBLOCK);
	if (dfd < 0) {
		lwsl_warn("%s: open %s failed %d\n", __func__, dirpath, errno);
		return 1; /* stop the walk, it isn't a dir we can act in */
	}

	lws_dir_rm_rf_at(dfd, lde->name, 0);
	close(dfd);

	return 0;
}

#else /* walk by path */

static int
lws_dir_rm_rf_entry(const char *dirpath, int *depth, struct lws_dir_entry *lde);

static int
lws_dir_rm_rf_inner_cb(const char *dirpath, void *user,
		       struct lws_dir_entry *lde)
{
	return lws_dir_rm_rf_entry(dirpath, (int *)user, lde);
}

static int
lws_dir_rm_rf_entry(const char *dirpath, int *depth, struct lws_dir_entry *lde)
{
	int recurse = 1;
	char *path;

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	path = lws_dir_compose(dirpath, lde->name);
	if (!path)
		return 1; /* OOM: stop rather than act on a partial walk */

	if (lde->type == LDOT_DIR) {
#if defined(WIN32) || defined(_WIN32)
		DWORD attr = GetFileAttributesA(path);

		/*
		 * Junctions and directory symlinks are reparse points that
		 * the dirent emulation reports as dirs.  Never walk into one:
		 * the rmdir() below (RemoveDirectory) removes the link itself,
		 * leaving what it points to alone.
		 */
		if (attr == INVALID_FILE_ATTRIBUTES ||
		    (attr & FILE_ATTRIBUTE_REPARSE_POINT))
			recurse = 0;
#elif !defined(__COVERITY__)
		char dummy[8];
		/*
		 * hm... eg, recursive dir symlinks can show up a LDOT_DIR
		 * here.  If it's a symlink, don't recurse into it.
		 *
		 * Notice we immediately discard dummy without looking in it.
		 * There is no way to get into trouble from its lack of NUL
		 * termination in dummy[].  We just wanted to know if it was
		 * a symlink at all.
		 *
		 * Hide this from Coverity since it flags any use of readlink()
		 * even if safe.
		 */
		if (readlink(path, dummy, sizeof(dummy)) >= 0)
			recurse = 0;
#endif
		if (recurse) {
			if (*depth >= LWS_DIR_RM_RF_MAX_DEPTH) {
				lwsl_warn("%s: depth limit, leaving %s\n",
					  __func__, path);
				lws_free(path);

				return 0;
			}
			(*depth)++;
			lws_dir(path, depth, lws_dir_rm_rf_inner_cb);
			(*depth)--;
		}

		if (rmdir(path))
			lwsl_warn("%s: rmdir %s failed %d\n", __func__, path, errno);
	} else {
		if (unlink(path)) {
#if defined(WIN32)
			SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
			if (unlink(path))
#else
			if (rmdir(path))
#endif
			lwsl_warn("%s: unlink %s failed %d (type %d)\n",
					__func__, path, errno, lde->type);
		}
	}

	lws_free(path);

	return 0;
}

int
lws_dir_rm_rf_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	int depth = 0;

	/* user is documented as ignored: our own depth rides on the inner cb */

	return lws_dir_rm_rf_entry(dirpath, &depth, lde);
}
#endif

#if !defined(WIN32) && !defined(_WIN32)
/*
 * Make the new link under a temp name and rename() it over \p path, so
 * anything opening \p path meanwhile finds either the old or the new target,
 * never nothing
 */

static int
lws_dir_symlink_replace(const char *path, const char *target)
{
	char tmp[512];
	int e;

	if (strlen(path) + 5 > sizeof(tmp)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	lws_snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	unlink(tmp); /* left over from an interrupted rotation */
	if (symlink(target, tmp))
		return -1;

	if (rename(tmp, path)) {
		e = errno; /* the rename's reason, not the cleanup's */
		unlink(tmp);
		errno = e;
		return -1;
	}

	return 0;
}
#endif

int
lws_dir_symlink_rotate(const char *cur, const char *target,
		       const char *cur_tag, const char *prev_tag)
{
#if !defined(WIN32) && !defined(_WIN32)
	size_t ct = strlen(cur_tag), pt = strlen(prev_tag);
	char prev[512], old[512];
	const char *p, *q;
	ssize_t n;
	int e;

	/* the tag names the link, so it's the last one in the path */
	p = NULL;
	for (q = strstr(cur, cur_tag); q && ct; q = strstr(q + 1, cur_tag))
		p = q;
	if (!p) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * We only learn what's outgoing here, nothing is decided on it that
	 * a change under us could exploit, and the replacement is atomic
	 */
	/* coverity[toctou] */
	n = readlink(cur, old, sizeof(old) - 1);
	if (n > 0) {
		old[n] = '\0';

		if (!strcmp(old, target))
			return 0; /* already current, nothing is outgoing */

		if (lws_ptr_diff_size_t(p, cur) + pt + strlen(p + ct) >=
								sizeof(prev)) {
			errno = ENAMETOOLONG;
			return -1;
		}

		lws_snprintf(prev, sizeof(prev), "%.*s%s%s",
			     (int)lws_ptr_diff_size_t(p, cur), cur, prev_tag,
			     p + ct);

		if (lws_dir_symlink_replace(prev, old))
			lwsl_warn("%s: unable to link %s: errno %d\n", __func__,
				  prev, errno);
	}

	if (lws_dir_symlink_replace(cur, target)) {
		e = errno; /* logging may disturb it */
		lwsl_err("%s: unable to link %s: errno %d\n", __func__, cur, e);
		errno = e;
		return -1;
	}

	return 0;
#else
	errno = ENOSYS;
	return -1;
#endif
}


#endif

struct lws_plugin *
lws_plugin_alloc(struct lws_plugin **pplugin)
{
	struct lws_plugin *pin = lws_malloc(sizeof(*pin), __func__);

	if (!pin)
		return NULL;

	pin->list = *pplugin;
	pin->basename[0] = '\0';
	*pplugin = pin;

	return pin;
}

#if defined(LWS_WITH_PLUGINS_API)

#if defined(LWS_BUILTIN_PLUGIN_NAMES)

extern const lws_plugin_protocol_t *builtin_pcols[];

int
lws_plugins_handle_builtin(struct lws_plugin **pplugin,
			   each_plugin_cb_t each, void *each_user)
{
	size_t n = 0;

	while (builtin_pcols[n]) {
		struct lws_plugin *pin = lws_plugin_alloc(pplugin);
		if (!pin)
			return 1;

		pin->u.l = NULL;
		pin->hdr = &builtin_pcols[n]->hdr;

		if (each)
			each(pin, each_user);

		n++;
	}

	return 0;
}
#endif

#if defined(LWS_WITH_NETWORK) && defined(LWS_WITH_PLUGINS_API)
struct lws_plugins_args {
	struct lws_plugin	**pplugin;
	const char		*_class;
	const char		*filter;
	each_plugin_cb_t	each;
	void			*each_user;
};

static unsigned int
lws_plugin_get_priority(const lws_plugin_header_t *hdr)
{
	if (hdr->api_magic >= 192)
		return hdr->priority;

	return 0;
}

static void
lws_plugins_sort(struct lws_plugin **pplugin)
{
	struct lws_plugin *p1, *p2, *prev;
	int swapped;

	if (!pplugin || !*pplugin || !(*pplugin)->list)
		return;

	do {
		swapped = 0;
		p1 = *pplugin;
		prev = NULL;

		while (p1->list) {
			p2 = p1->list;
			if (lws_plugin_get_priority(p1->hdr) <
			    lws_plugin_get_priority(p2->hdr)) {
				/* swap */
				p1->list = p2->list;
				p2->list = p1;
				if (prev)
					prev->list = p2;
				else
					*pplugin = p2;

				swapped = 1;
				prev = p2;
			} else {
				prev = p1;
				p1 = p1->list;
			}
		}
	} while (swapped);
}

static int
lws_plugins_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct lws_plugins_args *pa = (struct lws_plugins_args *)user;
	char path[256], base[64], *q = base;
	const lws_plugin_header_t *pl;
	const char *p;

	if (strlen(lde->name) < 7)
		return 0; /* keep going */

	/*
	 * The actual plugin names for protocol plugins look like
	 * "libprotocol_lws_ssh_base.so" and for event libs
	 * "libwebsockets-evlib_ev.so"... to recover the base name of
	 * "lws_ssh_base" and "evlib_ev" we strip from the left to after the
	 * first _ or -, and then truncate at the first .
	 */

	p = lde->name;
	while (*p && *p != '_' && *p != '-')
		p++;
	if (!*p)
		return 0;
	p++;
	while (*p && *p != '.' && lws_ptr_diff(q, base) < (int)sizeof(base) - 1)
		*q++ = *p++;
	*q = '\0';

	/* if he's given a filter, only match if base matches it */
	if (pa->filter && strcmp(base, pa->filter))
		return 0; /* keep going */

	/*
	 * The class is visible in the filename too: don't dlopen() files
	 * that cannot be the class we are scanning for.  Loading a protocol
	 * plugin just to find it is not an event lib brings in its whole
	 * dependency chain (codecs, OpenMP...), some of which cannot be
	 * cleanly unloaded again.
	 */

	if (!strcmp(pa->_class, "lws_evlib_plugin")) {
		if (strncmp(base, "evlib_", 6))
			return 0;
	} else if (!strcmp(pa->_class, "lws_protocol_plugin")) {
		p = lde->name;
		if (!strncmp(p, "lib", 3))
			p += 3;
		if (strncmp(p, "protocol_", 9))
			return 0;
	}

	/*
	 * Directory precedence: a plugin already loaded from an earlier
	 * directory is not opened again just to be found duplicate
	 */

	{
		struct lws_plugin *pin = *pa->pplugin;

		while (pin) {
			if (!strcmp(pin->basename, base))
				return 0; /* keep going */
			pin = pin->list;
		}
	}

	lws_snprintf(path, sizeof(path) - 1, "%s/%s", dirpath, lde->name);

	pl = lws_plat_dlopen(pa->pplugin, path, base, pa->_class,
			     NULL, NULL);

	/*
	 * If we were looking for a specific plugin, finding it should make
	 * us stop looking (eg, to account for directory precedence of the
	 * same plugin).  If scanning for plugins in a dir, we always keep
	 * going.
	 */

	return pa->filter && pl;
}

int
lws_plugins_init(struct lws_plugin **pplugin, const char * const *d,
		 const char *_class, const char *filter,
		 each_plugin_cb_t each, void *each_user)
{
	struct lws_plugins_args pa;
	char *ld_env;
	int ret = 1;

	pa.pplugin = pplugin;
	pa._class = _class;
	pa.each = each;
	pa.each_user = each_user;
	pa.filter = filter;

	/*
	 * Check LD_LIBRARY_PATH override path first if present
	 */

	ld_env = getenv("LD_LIBRARY_PATH");
	/*
	 * The dynamic loader ignores LD_LIBRARY_PATH for set-uid / set-gid
	 * (AT_SECURE) processes precisely so an unprivileged caller cannot
	 * pick the code a privileged process loads; scanning it ourselves
	 * for plugins to dlopen() would reintroduce that.  Honour the same
	 * rule.
	 */
	if (ld_env && lws_environment_untrusted())
		ld_env = NULL;
	if (ld_env) {
		char temp[128];
		struct lws_tokenize ts;

		memset(&ts, 0, sizeof(ts));
		ts.start = ld_env;
		ts.len = strlen(ld_env);
		ts.flags = LWS_TOKENIZE_F_SLASH_NONTERM |
			   LWS_TOKENIZE_F_DOT_NONTERM |
			   LWS_TOKENIZE_F_MINUS_NONTERM |
			   LWS_TOKENIZE_F_NO_INTEGERS |
			   LWS_TOKENIZE_F_NO_FLOATS;

		do {
			ts.e = (int8_t)lws_tokenize(&ts);
			if (ts.e != LWS_TOKZE_TOKEN)
				continue;

			lws_strnncpy(temp, ts.token,
				     ts.token_len,
				     sizeof(temp));

			lwsl_info("%s: trying %s\n", __func__, temp);
			if (!lws_dir(temp, &pa, lws_plugins_dir_cb))
				ret = 0;

		} while (ts.e > 0);
	}

	while (d && *d) {
		lwsl_info("%s: trying %s\n", __func__, *d);
		if (!lws_dir(*d, &pa, lws_plugins_dir_cb))
			ret = 0;

		d++;
	}

	if (*pplugin) {
		struct lws_plugin *p = *pplugin;

		lws_plugins_sort(pplugin);

		if (each) {
			p = *pplugin;
			while (p) {
				each(p, each_user);
				p = p->list;
			}
		}
	}

	return ret;
}

int
lws_plugins_destroy(struct lws_plugin **pplugin, each_plugin_cb_t each,
		    void *each_user)
{
	struct lws_plugin *p = *pplugin, *p1;

	while (p) {
		if (each)
			each(p, each_user);
		if (p->u.l)
			lws_plat_destroy_dl(p);
		p1 = p->list;
		p->list = NULL;
		lws_free(p);
		p = p1;
	}

	*pplugin = NULL;

	return 0;
}
#endif
#endif
