/*
 * libwebsockets - lib/plat/lws-plat-esp32.c
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "core/private.h"

int lws_plat_apply_FD_CLOEXEC(int n)
{
	return 0;
}


LWS_VISIBLE lws_fop_fd_t IRAM_ATTR
_lws_plat_file_open(const struct lws_plat_file_ops *fops, const char *filename,
		    const char *vpath, lws_fop_flags_t *flags)
{
	struct stat stat_buf;
	lws_fop_fd_t fop_fd;
	int ret = open(filename, *flags, 0664);

	if (ret < 0)
		return NULL;

	if (fstat(ret, &stat_buf) < 0)
		goto bail;

	fop_fd = lws_malloc(sizeof(*fop_fd), "fops open");
	if (!fop_fd)
		goto bail;

	fop_fd->fops = fops;
	fop_fd->fd = ret;
	fop_fd->flags = *flags;
	fop_fd->filesystem_priv = NULL; /* we don't use it */
	fop_fd->pos = 0;
	fop_fd->len = stat_buf.st_size;

	return fop_fd;

bail:
	close(ret);

	return NULL;
}

LWS_VISIBLE int IRAM_ATTR
_lws_plat_file_close(lws_fop_fd_t *fops_fd)
{
	int fd = (*fops_fd)->fd;

	lws_free(*fops_fd);
	*fops_fd = NULL;

	return close(fd);
}

LWS_VISIBLE lws_fileofs_t IRAM_ATTR
_lws_plat_file_seek_cur(lws_fop_fd_t fops_fd, lws_fileofs_t offset)
{
	return lseek(fops_fd->fd, offset, SEEK_CUR);
}

LWS_VISIBLE int IRAM_ATTR
_lws_plat_file_read(lws_fop_fd_t fops_fd, lws_filepos_t *amount,
		    uint8_t *buf, lws_filepos_t len)
{
	long n;

	n = read(fops_fd->fd, buf, len);
	if (n == -1) {
		*amount = 0;
		return -1;
	}
	fops_fd->pos += n;
	*amount = n;

	return 0;
}

LWS_VISIBLE int IRAM_ATTR
_lws_plat_file_write(lws_fop_fd_t fops_fd, lws_filepos_t *amount,
		     uint8_t *buf, lws_filepos_t len)
{
	long n;

	n = write(fops_fd->fd, buf, len);
	if (n == -1) {
		*amount = 0;
		return -1;
	}
	fops_fd->pos += n;
	*amount = n;

	return 0;
}

#if defined(LWS_AMAZON_RTOS)
int
lws_find_string_in_file(const char *filename, const char *string, int stringlen)
{
    return 0;
}
#else
int
lws_find_string_in_file(const char *filename, const char *string, int stringlen)
{
	nvs_handle nvh;
	size_t s;
	int n;
	char buf[64], result[64];
	const char *p = strchr(string, ':'), *q;

	if (!p)
		return 0;

	q = string;
	n = 0;
	while (n < sizeof(buf) - 1 && q != p)
		buf[n++] = *q++;
	buf[n] = '\0';

	ESP_ERROR_CHECK(nvs_open(filename, NVS_READWRITE, &nvh));

	s = sizeof(result) - 1;
	n = nvs_get_str(nvh, buf, result, &s);
	nvs_close(nvh);

	if (n != ESP_OK)
		return 0;

	return !strcmp(p + 1, result);
}
#endif

#if !defined(LWS_AMAZON_RTOS)
LWS_VISIBLE int
lws_plat_write_file(const char *filename, void *buf, int len)
{
	nvs_handle nvh;
	int n;

	if (nvs_open("lws-station", NVS_READWRITE, &nvh)) {
		lwsl_notice("%s: failed to open nvs\n", __func__);
		return -1;
	}

	n = nvs_set_blob(nvh, filename, buf, len);
	if (n >= 0)
		nvs_commit(nvh);

	nvs_close(nvh);

	lwsl_notice("%s: wrote %s (%d)\n", __func__, filename, n);

	return n;
}

/* we write vhostname.cert.pem and vhostname.key.pem, 0 return means OK */

LWS_VISIBLE int
lws_plat_write_cert(struct lws_vhost *vhost, int is_key, int fd, void *buf,
			int len)
{
	const char *name = vhost->tls.alloc_cert_path;

	if (is_key)
		name = vhost->tls.key_path;

	return lws_plat_write_file(name, buf, len) < 0;
}

LWS_VISIBLE int
lws_plat_read_file(const char *filename, void *buf, int len)
{
	nvs_handle nvh;
	size_t s = 0;
	int n = 0;

	if (nvs_open("lws-station", NVS_READWRITE, &nvh)) {
		lwsl_notice("%s: failed to open nvs\n", __func__);
		return 1;
	}

	ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));
	if (nvs_get_blob(nvh, filename, NULL, &s) != ESP_OK)
		goto bail;
	if (s > (size_t)len)
		goto bail;

	n = nvs_get_blob(nvh, filename, buf, &s);

	nvs_close(nvh);

	lwsl_notice("%s: read %s (%d)\n", __func__, filename, (int)s);

	if (n)
		return -1;

	return (int)s;

bail:
	nvs_close(nvh);

	return -1;
}
#endif /* LWS_AMAZON_RTOS */
