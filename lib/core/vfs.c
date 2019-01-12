/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2019 Andy Green <andy@warmcat.com>
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


LWS_VISIBLE LWS_EXTERN void
lws_set_fops(struct lws_context *context, const struct lws_plat_file_ops *fops)
{
	context->fops = fops;
}

LWS_VISIBLE LWS_EXTERN lws_filepos_t
lws_vfs_tell(lws_fop_fd_t fop_fd)
{
	return fop_fd->pos;
}

LWS_VISIBLE LWS_EXTERN lws_filepos_t
lws_vfs_get_length(lws_fop_fd_t fop_fd)
{
	return fop_fd->len;
}

LWS_VISIBLE LWS_EXTERN uint32_t
lws_vfs_get_mod_time(lws_fop_fd_t fop_fd)
{
	return fop_fd->mod_time;
}

LWS_VISIBLE lws_fileofs_t
lws_vfs_file_seek_set(lws_fop_fd_t fop_fd, lws_fileofs_t offset)
{
	lws_fileofs_t ofs;

	ofs = fop_fd->fops->LWS_FOP_SEEK_CUR(fop_fd, offset - fop_fd->pos);

	return ofs;
}


LWS_VISIBLE lws_fileofs_t
lws_vfs_file_seek_end(lws_fop_fd_t fop_fd, lws_fileofs_t offset)
{
	return fop_fd->fops->LWS_FOP_SEEK_CUR(fop_fd, fop_fd->len +
					      fop_fd->pos + offset);
}


const struct lws_plat_file_ops *
lws_vfs_select_fops(const struct lws_plat_file_ops *fops, const char *vfs_path,
		    const char **vpath)
{
	const struct lws_plat_file_ops *pf;
	const char *p = vfs_path;
	int n;

	*vpath = NULL;

	/* no non-platform fops, just use that */

	if (!fops->next)
		return fops;

	/*
	 *  scan the vfs path looking for indications we are to be
	 * handled by a specific fops
	 */

	while (p && *p) {
		if (*p != '/') {
			p++;
			continue;
		}
		/* the first one is always platform fops, so skip */
		pf = fops->next;
		while (pf) {
			n = 0;
			while (n < (int)LWS_ARRAY_SIZE(pf->fi) && pf->fi[n].sig) {
				if (p >= vfs_path + pf->fi[n].len)
					if (!strncmp(p - (pf->fi[n].len - 1),
						     pf->fi[n].sig,
						     pf->fi[n].len - 1)) {
						*vpath = p + 1;
						return pf;
					}

				n++;
			}
			pf = pf->next;
		}
		p++;
	}

	return fops;
}

LWS_VISIBLE LWS_EXTERN lws_fop_fd_t LWS_WARN_UNUSED_RESULT
lws_vfs_file_open(const struct lws_plat_file_ops *fops, const char *vfs_path,
		  lws_fop_flags_t *flags)
{
	const char *vpath = "";
	const struct lws_plat_file_ops *selected;

	selected = lws_vfs_select_fops(fops, vfs_path, &vpath);

	return selected->LWS_FOP_OPEN(fops, vfs_path, vpath, flags);
}


LWS_VISIBLE struct lws_plat_file_ops *
lws_get_fops(struct lws_context *context)
{
	return (struct lws_plat_file_ops *)context->fops;
}

