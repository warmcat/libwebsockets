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

#include <libwebsockets.h>
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

#define COMBO_SIZEOF 256

#if !defined(LWS_PLAT_FREERTOS)

#if defined(WIN32)
#include "../../win32port/dirent/dirent-win32.h"
#else
#include <dirent.h>
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

static void
lws_dir_via_stat(char *combo, size_t l, const char *path, struct lws_dir_entry *lde)
{
        struct stat s;

        lws_strncpy(combo + l, path, COMBO_SIZEOF - l);

        lde->type = LDOT_UNKNOWN;

        if (!stat(combo, &s)) {
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
}

int
lws_dir(const char *dirpath, void *user, lws_dir_callback_function cb)
{
	struct lws_dir_entry lde;
	struct dirent **namelist;
	int n, i, ret = 1;
	char combo[COMBO_SIZEOF];
	size_t l;

	l = lws_snprintf(combo, COMBO_SIZEOF - 2, "%s", dirpath);
	combo[l++] = csep;
	combo[l] = '\0';

	n = scandir((char *)dirpath, &namelist, filter, alphasort);
	if (n < 0) {
		lwsl_err("Scandir on '%s' failed, errno %d\n", dirpath, LWS_ERRNO);
		return 1;
	}

	for (i = 0; i < n; i++) {
		if (strchr(namelist[i]->d_name, '~'))
			goto skip;
		lde.name = namelist[i]->d_name;

		/*
		 * some filesystems don't report this (ZFS) and tell that
		 * files are LDOT_UNKNOWN
		 */

#if defined(__sun)
		lws_dir_via_stat(combo, l, namelist[i]->d_name, &lde);
#else
		/*
		 * XFS on Linux doesn't fill in d_type at all, always zero.
		 */

		switch (namelist[i]->d_type) {
#if DT_BLK != DT_UNKNOWN
		case DT_BLK:
			lde.type = LDOT_BLOCK;
			break;
#endif
#if DT_CHR != DT_UNKNOWN
		case DT_CHR:
			lde.type = LDOT_CHAR;
			break;
#endif
#if DT_DIR != DT_UNKNOWN
		case DT_DIR:
			lde.type = LDOT_DIR;
			break;
#endif
#if DT_FIFO != DT_UNKNOWN
		case DT_FIFO:
			lde.type = LDOT_FIFO;
			break;
#endif
#if DT_LNK != DT_UNKNOWN
		case DT_LNK:
			lde.type = LDOT_LINK;
			break;
#endif
		case DT_REG:
			lde.type = LDOT_FILE;
			break;
#if DT_SOCK != DT_UNKNOWN
		case DT_SOCK:
			lde.type = LDOTT_SOCKET;
			break;
#endif
		default:
			lde.type = LDOT_UNKNOWN;
			lws_dir_via_stat(combo, l, namelist[i]->d_name, &lde);
			break;
		}
#endif
		if (cb(dirpath, user, &lde)) {
			while (i++ < n)
				free(namelist[i]);
			goto bail;
		}
skip:
		free(namelist[i]);
	}

	ret = 0;

bail:
	free(namelist);

	return ret;
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

/*
 * We get passed a single filter string, like "*.txt" or "mydir/\*.rpm" or so.
 */

int
lws_dir_glob_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	lws_dir_glob_t *filter = (lws_dir_glob_t*)user;
	char path[384];

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	if (lde->type == LDOT_DIR)
		return 0;

	if (lws_dir_glob_check(lde->name, filter->filter)) {
		lws_snprintf(path, sizeof(path), "%s%c%s", dirpath, csep,
							   lde->name);
		filter->cb(filter->user, path);
	}

	return 0;
}

int
lws_dir_rm_rf_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	char path[384];

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	lws_snprintf(path, sizeof(path), "%s%c%s", dirpath, csep, lde->name);

	if (lde->type == LDOT_DIR) {
		lws_dir(path, NULL, lws_dir_rm_rf_cb);
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

	return 0;
}


#endif
