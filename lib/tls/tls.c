/*
 * libwebsockets - small server side websockets and web server implementation
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

#include "private-libwebsockets.h"

int
lws_alloc_vfs_file(struct lws_context *context, const char *filename,
		   uint8_t **buf, lws_filepos_t *amount)
{
	lws_filepos_t len;
	lws_fop_flags_t	flags = LWS_O_RDONLY;
	lws_fop_fd_t fops_fd = lws_vfs_file_open(
				lws_get_fops(context), filename, &flags);
	int ret = 1;

	if (!fops_fd)
		return 1;

	len = lws_vfs_get_length(fops_fd);

	*buf = lws_malloc((size_t)len, "lws_alloc_vfs_file");
	if (!*buf)
		goto bail;

	if (lws_vfs_file_read(fops_fd, amount, *buf, len))
		goto bail;

	ret = 0;
bail:
	lws_vfs_file_close(&fops_fd);

	return ret;
}

int
lws_ssl_anybody_has_buffered_read_tsi(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws *wsi, *wsi_next;

	wsi = pt->pending_read_list;
	while (wsi) {
		wsi_next = wsi->pending_read_list_next;
		pt->fds[wsi->position_in_fds_table].revents |=
			pt->fds[wsi->position_in_fds_table].events & LWS_POLLIN;
		if (pt->fds[wsi->position_in_fds_table].revents & LWS_POLLIN)
			return 1;

		wsi = wsi_next;
	}

	return 0;
}

LWS_VISIBLE void
lws_ssl_remove_wsi_from_buffered_list(struct lws *wsi)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	if (!wsi->pending_read_list_prev &&
	    !wsi->pending_read_list_next &&
	    pt->pending_read_list != wsi)
		/* we are not on the list */
		return;

	/* point previous guy's next to our next */
	if (!wsi->pending_read_list_prev)
		pt->pending_read_list = wsi->pending_read_list_next;
	else
		wsi->pending_read_list_prev->pending_read_list_next =
			wsi->pending_read_list_next;

	/* point next guy's previous to our previous */
	if (wsi->pending_read_list_next)
		wsi->pending_read_list_next->pending_read_list_prev =
			wsi->pending_read_list_prev;

	wsi->pending_read_list_prev = NULL;
	wsi->pending_read_list_next = NULL;
}

int
lws_tls_check_cert_lifetime(struct lws_vhost *v)
{
	union lws_tls_cert_info_results ir;
	time_t now = (time_t)lws_now_secs(), life = 0;
	int n;

	if (v->ssl_ctx && !v->skipped_certs) {

		if (now < 1464083026) /* May 2016 */
			/* our clock is wrong and we can't judge the certs */
			return -1;

		n = lws_tls_vhost_cert_info(v, LWS_TLS_CERT_INFO_VALIDITY_TO, &ir, 0);
		if (n)
			return -1;

		life = (ir.time - now) / (24 * 3600);
		lwsl_notice("   vhost %s: cert expiry: %dd\n", v->name, (int)life);
	} else
		lwsl_notice("   vhost %s: no cert\n", v->name);

	lws_broadcast(v->context, LWS_CALLBACK_VHOST_CERT_AGING, v,
		      (size_t)(ssize_t)life);

	return 0;
}

int
lws_tls_check_all_cert_lifetimes(struct lws_context *context)
{
	struct lws_vhost *v = context->vhost_list;

	while (v) {
		lws_tls_check_cert_lifetime(v);
		v = v->vhost_next;
	}

	return 0;
}

static int
lws_tls_extant(const char *name)
{
	/* it exists if we can open it... */
	int fd = open(name, O_RDONLY), n;
	char buf[1];

	if (fd < 0)
		return 1;

	/* and we can read at least one byte out of it */
	n = read(fd, buf, 1);
	close(fd);

	return n != 1;
}

/*
 * Returns 0 if the filepath "name" exists and can be read from.
 *
 * In addition, if "name".upd exists, backup "name" to "name.old.1"
 * and rename "name".upd to "name" before reporting its existence.
 *
 * There are four situations and three results possible:
 *
 * 1) LWS_TLS_EXTANT_NO: There are no certs at all (we are waiting for them to
 *    be provisioned)
 *
 * 2) There are provisioned certs written (xxx.upd) and we still have root
 *    privs... in this case we rename any existing cert to have a backup name
 *    and move the upd cert into place with the correct name.  This then becomes
 *    situation 4 for the caller.
 *
 * 3) LWS_TLS_EXTANT_ALTERNATIVE: There are provisioned certs written (xxx.upd)
 *    but we no longer have the privs needed to read or rename them.  In this
 *    case, indicate that the caller should use temp copies if any we do have
 *    rights to access.  This is normal after we have updated the cert.
 *
 * 4) LWS_TLS_EXTANT_YES: The certs are present with the correct name and we
 *    have the rights to read them.
 */

enum lws_tls_extant
lws_tls_use_any_upgrade_check_extant(const char *name)
{
	char buf[256];
	int n;

	lws_snprintf(buf, sizeof(buf) - 1, "%s.upd", name);
	if (!lws_tls_extant(buf)) {
		/* ah there is an updated file... how about the desired file? */
		if (!lws_tls_extant(name)) {
			/* rename the desired file */
			for (n = 0; n < 50; n++) {
				lws_snprintf(buf, sizeof(buf) - 1,
					     "%s.old.%d", name, n);
				if (!rename(name, buf))
					break;
			}
			if (n == 50) {
				lwsl_notice("unable to rename %s\n", name);

				return LWS_TLS_EXTANT_ALTERNATIVE;
			}
			lws_snprintf(buf, sizeof(buf) - 1, "%s.upd", name);
		}
		/* desired file is out of the way, rename the updated file */
		if (rename(buf, name)) {
			lwsl_notice("unable to rename %s to %s\n", buf, name);

			return LWS_TLS_EXTANT_ALTERNATIVE;
		}
	}

	if (lws_tls_extant(name))
		return LWS_TLS_EXTANT_NO;

	return LWS_TLS_EXTANT_YES;
}

int
lws_gate_accepts(struct lws_context *context, int on)
{
	struct lws_vhost *v = context->vhost_list;

	lwsl_info("gating accepts %d\n", on);
	context->ssl_gate_accepts = !on;
#if defined(LWS_WITH_STATS)
	context->updated = 1;
#endif

	while (v) {
		if (v->use_ssl && v->lserv_wsi &&
		    lws_change_pollfd(v->lserv_wsi, (LWS_POLLIN) * !on,
				      (LWS_POLLIN) * on))
			lwsl_info("Unable to set accept POLLIN %d\n", on);

		v = v->vhost_next;
	}

	return 0;
}
