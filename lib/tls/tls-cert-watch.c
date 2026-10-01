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
 * A server vhost whose cert and key are files notices them being renewed on
 * disk, and moves onto the new ones with lws_tls_vhost_cert_reload(), without
 * disturbing the connections it is serving.
 *
 * Whoever renews them, and however: an acme client in this process or
 * another, a cert distribution client fetching a copy from elsewhere, or
 * certbot, writing new files and moving a symlink onto them or rewriting them
 * in place.  The vhost only knows the paths it was configured with, and what
 * file each led to when its active ctx was loaded from it.
 *
 * The directories holding the configured paths are watched, with what
 * changes in them coalesced for a couple of seconds, since a renewal writes
 * the cert and the key one after the other.  Where a directory can't be
 * watched, and to cover a missed event, the paths are also looked at hourly.
 *
 * The new cert may be held back for the vhost's grace period
 * (info->tls_cert_grace_secs), counted from when it was issued or written,
 * whichever is later, eg, so that a DANE record for it has replaced cached
 * copies of the old one before it is served.  A CA may backdate a cert's
 * notBefore, so the file's mtime is the better guide to how new it is.
 *
 * A pair that fails to load, eg, a cert whose key is not written yet, is
 * retried, sooner when the files change again, else backing off to hourly.
 */

#include "private-lib-core.h"

#if defined(LWS_TLS_CERT_WATCH)

#include <sys/stat.h>

/* let a renewal finish writing its files before we look */
#define LWS_TLS_CERT_WATCH_SETTLE_US	(2 * LWS_US_PER_SEC)
/* the first look, once the context is up and any privileges are dropped */
#define LWS_TLS_CERT_WATCH_FIRST_US	(5 * LWS_US_PER_SEC)
#define LWS_TLS_CERT_WATCH_POLL_S	3600
#define LWS_TLS_CERT_WATCH_RETRY_S	60

struct lws_tls_cert_watch_dir {
	lws_dll2_t		list;	/* cx->tls.cert_watch_dirs */
#if defined(LWS_WITH_DIR)
	struct lws_dir_notify	*dn;
#endif
	/* the dir path is overallocated after us */
};

int
lws_tls_cert_file_id_get(const char *path, struct lws_tls_cert_file_id *id)
{
#if defined(WIN32) && defined(LWS_HAVE__STAT32I64)
	struct _stat32i64 s;
#else
	struct stat s;
#endif

	memset(id, 0, sizeof(*id));

	if (!path)
		return 1;

#if defined(WIN32) && defined(LWS_HAVE__STAT32I64)
	if (_stat32i64(path, &s))
#else
	if (stat(path, &s))
#endif
		return 1;

	id->dev		= (uint64_t)s.st_dev;
	id->ino		= (uint64_t)s.st_ino;
	id->size	= (int64_t)s.st_size;
	id->mtime	= (int64_t)s.st_mtime;
	id->valid	= 1;

	return 0;
}

static int
lws_tls_cert_file_id_same(const struct lws_tls_cert_file_id *a,
			  const struct lws_tls_cert_file_id *b)
{
	return a->valid && b->valid && a->dev == b->dev && a->ino == b->ino &&
	       a->size == b->size && a->mtime == b->mtime;
}

static void
lws_tls_cert_watch_sul_cb(lws_sorted_usec_list_t *sul);

static void
lws_tls_cert_watch_schedule(struct lws_context *cx, lws_usec_t us)
{
	lws_sul_schedule(cx, 0, &cx->tls.sul_cert_watch,
			 lws_tls_cert_watch_sul_cb, us);
}

#if defined(LWS_WITH_DIR)
static void
lws_tls_cert_watch_dir_cb(const char *path, int is_file, void *user)
{
	struct lws_context *cx = (struct lws_context *)user;

	(void)path;
	(void)is_file;

	/* coalesce what a renewal writes, a look once it has settled */
	lws_tls_cert_watch_schedule(cx, LWS_TLS_CERT_WATCH_SETTLE_US);
}
#endif

/*
 * Watch the directory holding path, if nothing is watching it yet.  It is the
 * directory of the path as configured, not where a symlink there leads: a
 * renewal moves the symlink, so that is where the change is seen.
 */

static void
lws_tls_cert_watch_dir_add(struct lws_context *cx, const char *path)
{
	struct lws_tls_cert_watch_dir *wd;
	const char *p = path, *slash = NULL;
	char dir[256];
	size_t n;

	for (; *p; p++)
		if (*p == '/'
#if defined(WIN32)
		    || *p == '\\'
#endif
		   )
			slash = p;

	if (!slash)
		lws_strncpy(dir, ".", sizeof(dir));
	else {
		n = (size_t)(slash - path);
		if (!n)
			n = 1; /* the root dir keeps its slash */
		if (n >= sizeof(dir)) {
			lwsl_cx_warn(cx, "cert dir of %s too long to watch", path);
			return;
		}
		memcpy(dir, path, n);
		dir[n] = '\0';
	}

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->tls.cert_watch_dirs)) {
		wd = lws_container_of(d, struct lws_tls_cert_watch_dir, list);
		if (!strcmp((const char *)&wd[1], dir))
			return;
	} lws_end_foreach_dll(d);

	n = strlen(dir) + 1;
	wd = lws_zalloc(sizeof(*wd) + n, __func__);
	if (!wd)
		return;
	memcpy(&wd[1], dir, n);

#if defined(LWS_WITH_DIR)
	wd->dn = lws_dir_notify_create(cx, dir, lws_tls_cert_watch_dir_cb, cx);
	if (!wd->dn)
#endif
		/*
		 * Kept on the list anyway, so we don't try again for every
		 * vhost with a cert in it: the hourly look covers it
		 */
		lwsl_cx_notice(cx, "can't watch %s, cert renewals in it are "
				   "only seen hourly", dir);

	lws_dll2_add_tail(&wd->list, &cx->tls.cert_watch_dirs);
}

/*
 * Look at one vhost's files, and move it onto them if they changed.  *next is
 * brought forward to when it next needs looking at, if that is sooner.
 */

static void
lws_tls_cert_watch_check_vhost(struct lws_vhost *v, time_t now, time_t *next)
{
	struct lws_tls_cert_file_id idc, idk;
	time_t not_before, due;

	if (!v->tls.watch_dirs_added) {
		lws_tls_cert_watch_dir_add(v->context, v->tls.cfg_alloc_cert_path);
		lws_tls_cert_watch_dir_add(v->context, v->tls.cfg_key_path);
		v->tls.watch_dirs_added = 1;
	}

	if (lws_tls_cert_file_id_get(v->tls.cfg_alloc_cert_path, &idc) ||
	    lws_tls_cert_file_id_get(v->tls.cfg_key_path, &idk)) {
		/*
		 * Not there yet, mid-replacement, or we can't reach them, eg,
		 * since we dropped the privileges we loaded them with
		 */
		if (!v->tls.watch_unseen)
			lwsl_vhost_warn(v, "can't see cert %s or key %s (errno %d), "
					"won't see them renewed until we can",
					v->tls.cfg_alloc_cert_path,
					v->tls.cfg_key_path, errno);
		v->tls.watch_unseen = 1;

		return;
	}

	if (v->tls.watch_unseen)
		lwsl_vhost_notice(v, "cert %s and key %s can be seen again",
				  v->tls.cfg_alloc_cert_path, v->tls.cfg_key_path);
	v->tls.watch_unseen = 0;

	if (lws_tls_cert_file_id_same(&idc, &v->tls.watch_cert) &&
	    lws_tls_cert_file_id_same(&idk, &v->tls.watch_key))
		return; /* what the active ctx was loaded from */

	if (!lws_tls_cert_file_id_same(&idc, &v->tls.seen_cert) ||
	    !lws_tls_cert_file_id_same(&idk, &v->tls.seen_key)) {
		/* a change we have not seen before is tried at once */
		lwsl_vhost_notice(v, "cert %s or key %s changed",
				  v->tls.cfg_alloc_cert_path, v->tls.cfg_key_path);
		v->tls.seen_cert	= idc;
		v->tls.seen_key		= idk;
		v->tls.watch_retry_at	= 0;
		v->tls.watch_backoff_s	= 0;
	}

	if (now < v->tls.watch_retry_at) {
		if (v->tls.watch_retry_at < *next)
			*next = v->tls.watch_retry_at;

		return;
	}

	/*
	 * The grace period only holds back a cert that would replace one being
	 * served: a vhost that had none takes it at once
	 */

	if (v->tls.cert_grace_secs && v->tls.ssl_ctx && v->tls.watch_cert.valid) {
		if (lws_tls_cert_get_x509_validity(v->context,
						   v->tls.cfg_alloc_cert_path,
						   &not_before, NULL))
			goto failed; /* eg, not completely written yet */

		due = not_before > (time_t)idc.mtime ? not_before :
						       (time_t)idc.mtime;
		due += (time_t)v->tls.cert_grace_secs;

		if (now < due) {
			lwsl_vhost_info(v, "new cert %s waits %llds for its "
					"grace period", v->tls.cfg_alloc_cert_path,
					(long long)(due - now));
			if (due < *next)
				*next = due;

			return;
		}
	}

	if (!lws_tls_vhost_cert_reload(v, NULL, 0, NULL, 0)) {
		v->tls.watch_retry_at	= 0;
		v->tls.watch_backoff_s	= 0;

		return;
	}

failed:
	v->tls.watch_backoff_s = v->tls.watch_backoff_s ?
			v->tls.watch_backoff_s * 2 : LWS_TLS_CERT_WATCH_RETRY_S;
	if (v->tls.watch_backoff_s > LWS_TLS_CERT_WATCH_POLL_S)
		v->tls.watch_backoff_s = LWS_TLS_CERT_WATCH_POLL_S;
	v->tls.watch_retry_at = now + (time_t)v->tls.watch_backoff_s;
	if (v->tls.watch_retry_at < *next)
		*next = v->tls.watch_retry_at;

	lwsl_vhost_err(v, "unable to move onto the changed cert %s / key %s, "
		       "retrying in %us", v->tls.cfg_alloc_cert_path,
		       v->tls.cfg_key_path, (unsigned int)v->tls.watch_backoff_s);
}

static void
lws_tls_cert_watch_sul_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context *cx = lws_container_of(sul, struct lws_context,
						  tls.sul_cert_watch);
	time_t now = (time_t)lws_now_secs(),
	       next = now + LWS_TLS_CERT_WATCH_POLL_S;

	lws_start_foreach_vhost(v, cx) {
		if (v->tls.watched && !v->being_destroyed)
			lws_tls_cert_watch_check_vhost(v, now, &next);
	} lws_end_foreach_vhost(v);

	/* never longer than the poll, whatever the wall clock is doing */
	if (next <= now || next > now + LWS_TLS_CERT_WATCH_POLL_S)
		next = now + (next <= now ? 1 : LWS_TLS_CERT_WATCH_POLL_S);

	lws_tls_cert_watch_schedule(cx, (lws_usec_t)(next - now) *
					LWS_US_PER_SEC);
}

/*
 * The vhost's active ctx was just loaded from its configured files, which
 * were cert and key then (NULL if it came up without them).  The directories
 * are watched from the first look, a little later: by then, a server that
 * drops its privileges has done so, and we watch only what it can still see.
 */

void
lws_tls_cert_watch_vhost(struct lws_vhost *v,
			 const struct lws_tls_cert_file_id *cert,
			 const struct lws_tls_cert_file_id *key)
{
	struct lws_context *cx = v->context;

	if (cx->deprecated || cx->being_destroyed)
		return;

	if (cert && key) {
		v->tls.watch_cert	= *cert;
		v->tls.watch_key	= *key;
	}
	v->tls.watched = 1;

	if (!lws_dll2_is_detached(&cx->tls.sul_cert_watch.list))
		return; /* the first look is already coming */

	lws_tls_cert_watch_schedule(cx, LWS_TLS_CERT_WATCH_FIRST_US);
}

void
lws_tls_cert_watch_destroy(struct lws_context *cx)
{
	lws_sul_cancel(&cx->tls.sul_cert_watch);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&cx->tls.cert_watch_dirs)) {
		struct lws_tls_cert_watch_dir *wd = lws_container_of(d,
				struct lws_tls_cert_watch_dir, list);

		lws_dll2_remove(&wd->list);
#if defined(LWS_WITH_DIR)
		lws_dir_notify_destroy(&wd->dn);
#endif
		lws_free(wd);
	} lws_end_foreach_dll_safe(d, d1);

	/* nothing more is looked at, eg, by a deprecated context */
	lws_start_foreach_vhost(v, cx) {
		v->tls.watched = 0;
		v->tls.watch_dirs_added = 0;
	} lws_end_foreach_vhost(v);
}

#endif
