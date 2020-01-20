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

#if defined(LWS_WITH_LIBUV) && UV_VERSION_MAJOR > 0

int
lws_dir(const char *dirpath, void *user, lws_dir_callback_function cb)
{
	struct lws_dir_entry lde;
	uv_dirent_t dent;
	uv_fs_t req;
	int ret = 1, ir;
	uv_loop_t loop;

	ir = uv_loop_init(&loop);
	if (ir) {
		lwsl_err("%s: loop init failed %d\n", __func__, ir);
	}

	ir = uv_fs_scandir(&loop, &req, dirpath, 0, NULL);
	if (ir < 0) {
		lwsl_err("Scandir on %s failed, errno %d\n", dirpath, LWS_ERRNO);
		return 2;
	}

	while (uv_fs_scandir_next(&req, &dent) != UV_EOF) {
		lde.name = dent.name;
		lde.type = (int)dent.type;
		if (cb(dirpath, user, &lde))
			goto bail;
	}

	ret = 0;

bail:
	uv_fs_req_cleanup(&req);
	while (uv_loop_close(&loop))
		;

	return ret;
}

#else

#if !defined(_WIN32) && !defined(LWS_PLAT_FREERTOS)

#include <dirent.h>

static int filter(const struct dirent *ent)
{
	if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
		return 0;

	return 1;
}

int
lws_dir(const char *dirpath, void *user, lws_dir_callback_function cb)
{
	struct lws_dir_entry lde;
	struct dirent **namelist;
	int n, i, ret = 1;

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
        struct stat s;
        stat(namelist[i]->d_name, &s);
		switch (s.st_mode) {
		case S_IFBLK:
			lde.type = LDOT_BLOCK;
			break;
		case S_IFCHR:
			lde.type = LDOT_CHAR;
			break;
		case S_IFDIR:
			lde.type = LDOT_DIR;
			break;
		case S_IFIFO:
			lde.type = LDOT_FIFO;
			break;
		case S_IFLNK:
			lde.type = LDOT_LINK;
			break;
		case S_IFREG:
			lde.type = LDOT_FILE;
			break;
		default:
			lde.type = LDOT_UNKNOWN;
			break;
		}
#else
		switch (namelist[i]->d_type) {
		case DT_BLK:
			lde.type = LDOT_BLOCK;
			break;
		case DT_CHR:
			lde.type = LDOT_CHAR;
			break;
		case DT_DIR:
			lde.type = LDOT_DIR;
			break;
		case DT_FIFO:
			lde.type = LDOT_FIFO;
			break;
		case DT_LNK:
			lde.type = LDOT_LINK;
			break;
		case DT_REG:
			lde.type = LDOT_FILE;
			break;
		case DT_SOCK:
			lde.type = LDOTT_SOCKET;
			break;
		default:
			lde.type = LDOT_UNKNOWN;
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

#else
#error "If you want lws_dir on windows, you need libuv"
#endif
#endif
