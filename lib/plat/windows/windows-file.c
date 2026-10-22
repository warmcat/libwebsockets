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

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include "private-lib-core.h"

int lws_plat_apply_FD_CLOEXEC(int n)
{
	return 0;
}

/*
 * Win32 treats '\' and '/' identically as path separators and resolves ".."
 * itself inside CreateFileW() etc.  Generic path sanitisers (eg, the http
 * URI one, which normalises "/../" away) only know about '/', so a '\' can
 * carry a ".." component past them and out of the mount.
 *
 * Refuse those here, at the last moment before the path becomes a real Win32
 * path.  A ".." bounded by '\' has no legitimate use in lws (relative paths
 * given by the application use '/'), and neither does a ':' anywhere except
 * as the drive letter at [1] (it otherwise names an NTFS alternate data
 * stream, which is another way to get at a file the caller did not mean).
 */

static int
lws_plat_path_ok(const char *filename)
{
	const char *p = filename;
	size_t n;

	for (n = 0; filename[n]; n++)
		if (filename[n] == ':' && n != 1)
			return 0;

	while (*p) {
		if (p[0] == '.' && p[1] == '.' &&
		    /* is it a whole path component? */
		    (p == filename || p[-1] == '/' || p[-1] == '\\') &&
		    (!p[2] || p[2] == '/' || p[2] == '\\') &&
		    /* is a '\' one of its separators? */
		    ((p != filename && p[-1] == '\\') || p[2] == '\\'))
			return 0;

		p++;
	}

	return 1;
}

/*
 * Win32 maps a final path component naming a DOS device (CON, PRN, AUX, NUL,
 * COM0-9, LPT0-9, CONIN$, CONOUT$, with superscript 1 - 3 too for COM and
 * LPT) to the device, in any directory, case-insensitively, and ignoring
 * trailing spaces before an extension, which on Windows 10 and Server 2016 -
 * 2022 may be anything (eg, "com1.html").  Opening one opens the device:
 * a console or serial port then blocks the reader, and even the open can do
 * things to the hardware.  Refuse them before the open; the file type check
 * after it is the backstop for any other way to name a device.
 */

static int
lws_plat_path_is_device(const char *filename)
{
	static const char * const devs[] = {
		"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"
	};
	const char *p = filename, *base = filename;
	char b[8];
	size_t n = 0, m;

	for (; *p; p++)
		if (*p == '/' || *p == '\\')
			base = p + 1;

	/* the name up to any extension, uppercased */
	for (p = base; *p && *p != '.' && *p != ':'; p++) {
		if (n == sizeof(b) - 1) {
			if (*p != ' ')
				return 0; /* longer than any device name */
			continue; /* trailing spaces go anyway */
		}
		b[n++] = (char)toupper((unsigned char)*p);
	}
	while (n && b[n - 1] == ' ')
		n--;
	b[n] = '\0';

	for (m = 0; m < LWS_ARRAY_SIZE(devs); m++)
		if (!strcmp(b, devs[m]))
			return 1;

	if (n < 4 || (strncmp(b, "COM", 3) && strncmp(b, "LPT", 3)))
		return 0;

	/* COMn / LPTn, or COM / LPT and a superscript 1, 2 or 3 in UTF-8 */
	return (n == 4 && b[3] >= '0' && b[3] <= '9') ||
	       (n == 5 && (unsigned char)b[3] == 0xc2 &&
		((unsigned char)b[4] == 0xb9 || (unsigned char)b[4] == 0xb2 ||
		 (unsigned char)b[4] == 0xb3));
}

int
lws_plat_path_canonical(const char *path, char *buf, size_t len)
{
	WCHAR w[MAX_PATH], fin[MAX_PATH + 8];
	HANDLE h;
	DWORD n;

	if (MultiByteToWideChar(CP_UTF8, 0, path, -1, w,
				(int)LWS_ARRAY_SIZE(w)) <= 0)
		return 1;

	/* no access to the contents, and backup semantics to open a dir */
	h = CreateFileW(w, 0, FILE_SHARE_READ | FILE_SHARE_WRITE |
			      FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return 1;

	/* the name the filesystem opened: long names, as they are cased */
	n = GetFinalPathNameByHandleW(h, fin, (DWORD)LWS_ARRAY_SIZE(fin),
				      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
	CloseHandle(h);
	if (!n || n >= LWS_ARRAY_SIZE(fin))
		return 1;

	return WideCharToMultiByte(CP_UTF8, 0, fin, -1, buf, (int)len,
				   NULL, NULL) <= 0;
}

lws_fop_fd_t
_lws_plat_file_open(const struct lws_plat_file_ops *fops_own,
		    const struct lws_plat_file_ops *fops, const char *filename,
		    const char *vpath, lws_fop_flags_t *flags)
{
	HANDLE ret;
	WCHAR buf[MAX_PATH];
	lws_fop_fd_t fop_fd;
	LARGE_INTEGER llFileSize = {0};

	if (!lws_plat_path_ok(filename) || lws_plat_path_is_device(filename)) {
		lwsl_err("%s: refusing path '%s'\n", __func__, filename);

		return NULL;
	}

	/*
	 * If the conversion does not fit, MultiByteToWideChar() returns 0 and
	 * leaves buf unterminated... CreateFileW() would then read off the end
	 * of the stack array looking for the NUL
	 */

	if (MultiByteToWideChar(CP_UTF8, 0, filename, -1, buf,
				(int)LWS_ARRAY_SIZE(buf)) <= 0) {
		lwsl_err("%s: unable to convert path (%d)\n", __func__,
			 (int)GetLastError());

		return NULL;
	}

	if (((*flags) & 7) == _O_RDONLY)
		ret = CreateFileW(buf, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
				  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	else
		ret = CreateFileW(buf, GENERIC_WRITE, 0, NULL,
				  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (ret == INVALID_HANDLE_VALUE)
		goto bail;

	/*
	 * Only a file on a disk: not a device, a pipe or a socket however it
	 * was named, nor anything whose size we can't know
	 */
	if (GetFileType(ret) != FILE_TYPE_DISK ||
	    !GetFileSizeEx(ret, &llFileSize)) {
		lwsl_err("%s: refusing '%s': not a disk file\n", __func__,
			 filename);
		goto bail_close;
	}

	fop_fd = malloc(sizeof(*fop_fd));
	if (!fop_fd)
		goto bail_close;

	fop_fd->fops = fops;
#if defined(__MINGW32__)
	/* we use filesystem_priv */
	fop_fd->fd = (int)(intptr_t)ret;
#else
	fop_fd->fd = ret;
#endif
	fop_fd->filesystem_priv = ret;
	fop_fd->flags = *flags;
	fop_fd->len = llFileSize.QuadPart;
	fop_fd->pos = 0;

	return fop_fd;

bail_close:
	CloseHandle(ret);
bail:
	return NULL;
}

int
_lws_plat_file_close(lws_fop_fd_t *fop_fd)
{
	HANDLE fd = (*fop_fd)->filesystem_priv;

	free(*fop_fd);
	*fop_fd = NULL;

	CloseHandle((HANDLE)fd);

	return 0;
}

lws_fileofs_t
_lws_plat_file_seek_cur(lws_fop_fd_t fop_fd, lws_fileofs_t offset)
{
	LARGE_INTEGER l;

	l.QuadPart = offset;
	if (!SetFilePointerEx((HANDLE)fop_fd->filesystem_priv, l, NULL, FILE_CURRENT))
	{
		lwsl_err("error seeking from cur %ld, offset %ld\n", (long)fop_fd->pos, (long)offset);
		return -1;
	}

	LARGE_INTEGER zero;
	zero.QuadPart = 0;
	LARGE_INTEGER newPos;
	if (!SetFilePointerEx((HANDLE)fop_fd->filesystem_priv, zero, &newPos, FILE_CURRENT))
	{
		lwsl_err("error seeking from cur %ld, offset %ld\n", (long)fop_fd->pos, (long)offset);
		return -1;
	}
	fop_fd->pos = newPos.QuadPart;

	return newPos.QuadPart;
}

int
_lws_plat_file_read(lws_fop_fd_t fop_fd, lws_filepos_t *amount,
		    uint8_t *buf, lws_filepos_t len)
{
	DWORD _amount;

	if (!ReadFile((HANDLE)fop_fd->filesystem_priv, buf, (DWORD)len, &_amount, NULL)) {
		*amount = 0;

		/* the fops contract is < 0 on failure, callers test that */
		return -1;
	}

	fop_fd->pos += _amount;
	*amount = (unsigned long)_amount;

	return 0;
}

int
_lws_plat_file_write(lws_fop_fd_t fop_fd, lws_filepos_t *amount,
			 uint8_t* buf, lws_filepos_t len)
{
	DWORD _amount;

	if (!WriteFile((HANDLE)fop_fd->filesystem_priv, buf, (DWORD)len, &_amount, NULL)) {
		*amount = 0;

		return -1;
	}

	fop_fd->pos += _amount;
	*amount = (unsigned long)_amount;

	return 0;
}


int
lws_plat_write_cert(struct lws_vhost *vhost, int is_key, int fd, void *buf,
			size_t len)
{
	int n;

	n = (int)write(fd, buf, (unsigned int)len);

	lseek(fd, 0, SEEK_SET);

	return (size_t)n != len;
}

int
lws_plat_write_file(const char *filename, void *buf, size_t len)
{
	int m, fd;

	fd = lws_open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	if (fd == -1)
		return -1;

	m = (int)write(fd, buf, (unsigned int)len);
	close(fd);

	return (size_t)m != len;
}

int
lws_plat_read_file(const char *filename, void *buf, size_t len)
{
	int n, fd = lws_open(filename, O_RDONLY);
	if (fd == -1)
		return -1;

	n = (int)read(fd, buf, (unsigned int)len);
	close(fd);

	return n;
}

