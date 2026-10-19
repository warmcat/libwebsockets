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

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "private-lib-core.h"

#include <pwd.h>
#include <grp.h>

#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
static void
_lws_plat_apply_caps(unsigned int mode, const cap_value_t *cv, int count)
{
	cap_t caps;

	if (!count)
		return;

	caps = cap_get_proc();

	cap_set_flag(caps, (cap_flag_t)mode, count, cv, CAP_SET);
	cap_set_proc(caps);
	prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
	cap_free(caps);
}
#endif

/*
 * The reentrant passwd / group lookups take a caller buffer for the entry's
 * strings.  A fixed one is not enough: a group with a long member list (big
 * /etc/group lines, LDAP / SSSD) easily overflows 1KiB, and the lookup then
 * fails with ERANGE for an entry that exists.  Start from the size the
 * platform suggests and grow on ERANGE, up to a sane limit.
 */

#define LWS_PLAT_ID_BUF_DEFAULT		1024
#define LWS_PLAT_ID_BUF_LIMIT		(1024 * 1024)

typedef enum {
	LWS_PLAT_ID_USER_BY_NAME,
	LWS_PLAT_ID_USER_BY_UID,
	LWS_PLAT_ID_GROUP_BY_NAME,
	LWS_PLAT_ID_GROUP_BY_GID,
} lws_plat_id_kind_t;

typedef struct lws_plat_id_lookup {
	struct passwd		pw;
	struct group		gr;
	struct passwd		*p;	/* the user entry, if a user lookup */
	struct group		*g;	/* the group entry, if a group lookup */
	char			*buf;	/* backs the entry's strings */
} lws_plat_id_lookup_t;

static size_t
lws_plat_id_buf_hint(lws_plat_id_kind_t kind)
{
	long n = -1;

#if defined(_SC_GETPW_R_SIZE_MAX)
	if (kind == LWS_PLAT_ID_USER_BY_NAME || kind == LWS_PLAT_ID_USER_BY_UID)
		n = sysconf(_SC_GETPW_R_SIZE_MAX);
#endif
#if defined(_SC_GETGR_R_SIZE_MAX)
	if (kind == LWS_PLAT_ID_GROUP_BY_NAME || kind == LWS_PLAT_ID_GROUP_BY_GID)
		n = sysconf(_SC_GETGR_R_SIZE_MAX);
#endif
	(void)kind;

	/* -1 means the platform has no suggestion */

	if (n < LWS_PLAT_ID_BUF_DEFAULT || n > LWS_PLAT_ID_BUF_LIMIT)
		return LWS_PLAT_ID_BUF_DEFAULT;

	return (size_t)n;
}

static void
lws_plat_id_lookup_destroy(lws_plat_id_lookup_t *lk)
{
	lws_free_set_NULL(lk->buf);
	lk->p = NULL;
	lk->g = NULL;
}

/*
 * Find a user or group entry by name (name) or by id (id).  Returns 0 with
 * lk->p or lk->g set to the entry, which stays valid until
 * lws_plat_id_lookup_destroy(lk); otherwise ENOENT if there is no such
 * entry, or the errno of the failed lookup.  Either way, the caller must
 * lws_plat_id_lookup_destroy(lk) afterwards.
 */

static int
lws_plat_id_lookup(lws_plat_id_lookup_t *lk, lws_plat_id_kind_t kind,
		   const char *name, unsigned int id)
{
	size_t len = lws_plat_id_buf_hint(kind);
	int r;

	memset(lk, 0, sizeof(*lk));

	do {
		lk->buf = lws_malloc(len, __func__);
		if (!lk->buf)
			return ENOMEM;

		errno = 0;

		switch (kind) {
		case LWS_PLAT_ID_USER_BY_NAME:
#if defined(LWS_HAVE_GETPWNAM_R)
			r = getpwnam_r(name, &lk->pw, lk->buf, len, &lk->p);
#else
			lk->p = getpwnam(name);
			r = lk->p ? 0 : errno;
#endif
			break;
		case LWS_PLAT_ID_USER_BY_UID:
#if defined(LWS_HAVE_GETPWUID_R)
			r = getpwuid_r((uid_t)id, &lk->pw, lk->buf, len, &lk->p);
#else
			lk->p = getpwuid((uid_t)id);
			r = lk->p ? 0 : errno;
#endif
			break;
		case LWS_PLAT_ID_GROUP_BY_NAME:
#if defined(LWS_HAVE_GETGRNAM_R)
			r = getgrnam_r(name, &lk->gr, lk->buf, len, &lk->g);
#else
			lk->g = getgrnam(name);
			r = lk->g ? 0 : errno;
#endif
			break;
		default: /* LWS_PLAT_ID_GROUP_BY_GID */
#if defined(LWS_HAVE_GETGRGID_R)
			r = getgrgid_r((gid_t)id, &lk->gr, lk->buf, len, &lk->g);
#else
			lk->g = getgrgid((gid_t)id);
			r = lk->g ? 0 : errno;
#endif
			break;
		}

		if (r != ERANGE)
			break;

		/* the entry is bigger than the buffer: try again bigger */

		lws_free_set_NULL(lk->buf);
		len *= 2;
	} while (len <= LWS_PLAT_ID_BUF_LIMIT);

	if (r)
		return r;

	if (!lk->p && !lk->g)
		return ENOENT;

	return 0;
}

int
lws_plat_user_to_uid(const char *username, uid_t *puid)
{
	lws_plat_id_lookup_t lk;
	int n;

	if (!username || !username[0])
		return 1;

	/* check if numeric string (only digits, so no sign and no whitespace) */

	if (username[0] >= '0' && username[0] <= '9') {
		char *endptr = NULL;
		long val;

		errno = 0;
		val = strtol(username, &endptr, 10);

		/*
		 * uid_t is usually a 32-bit type while long is 64-bit... an id
		 * that does not fit must be rejected rather than truncated,
		 * since eg "4294967296" would otherwise silently become uid 0
		 */

		if (*endptr || errno || val < 0 || (long)(uid_t)val != val ||
		    (uid_t)val == (uid_t)-1) {
			lwsl_err("%s: uid '%s' out of range\n", __func__,
				 username);

			return 1;
		}

		*puid = (uid_t)val;

		return 0;
	}

	n = lws_plat_id_lookup(&lk, LWS_PLAT_ID_USER_BY_NAME, username, 0);
	if (!n)
		*puid = lk.p->pw_uid;
	else
		lwsl_err("%s: unknown user '%s' (%d)\n", __func__, username, n);

	lws_plat_id_lookup_destroy(&lk);

	return !!n;
}

int
lws_plat_group_to_gid(const char *groupname, gid_t *pgid)
{
	lws_plat_id_lookup_t lk;
	int n;

	if (!groupname || !groupname[0])
		return 1;

	/* check if numeric string (only digits, so no sign and no whitespace) */

	if (groupname[0] >= '0' && groupname[0] <= '9') {
		char *endptr = NULL;
		long val;

		errno = 0;
		val = strtol(groupname, &endptr, 10);

		/* as for the uid above, do not truncate an out-of-range id */

		if (*endptr || errno || val < 0 || (long)(gid_t)val != val ||
		    (gid_t)val == (gid_t)-1) {
			lwsl_err("%s: gid '%s' out of range\n", __func__,
				 groupname);

			return 1;
		}

		*pgid = (gid_t)val;

		return 0;
	}

	n = lws_plat_id_lookup(&lk, LWS_PLAT_ID_GROUP_BY_NAME, groupname, 0);
	if (!n)
		*pgid = lk.g->gr_gid;
	else
		lwsl_err("%s: unknown group '%s' (%d)\n", __func__, groupname,
			 n);

	lws_plat_id_lookup_destroy(&lk);

	return !!n;
}

int
lws_plat_user_colon_group_to_ids(const char *u_colon_g, uid_t *puid, gid_t *pgid)
{
	const char *colon = strchr(u_colon_g, ':');
	char u[33];
	size_t ulen;

	if (!colon)
		return 1;

	ulen = (size_t)(unsigned int)lws_ptr_diff(colon, u_colon_g);
	if (ulen < 1 || ulen > sizeof(u) - 1)
		return 1;

	memcpy(u, u_colon_g, ulen);
	u[ulen] = '\0';

	colon++;

	if (lws_plat_group_to_gid(colon, pgid))
		return 1;

	if (lws_plat_user_to_uid(u, puid))
		return 1;

	return 0;
}

#if defined(LWS_WITH_UNIX_SOCK)
int
lws_plat_unix_peer_ids(lws_sockfd_type fd, uid_t *puid, gid_t *pgid)
{
#if defined(__linux__)
	struct ucred cr;
	socklen_t len = sizeof(cr);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) ||
	    len != sizeof(cr))
		return 1;

	*puid = cr.uid;
	*pgid = cr.gid;

	return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
      defined(__OpenBSD__) || defined(__DragonFly__)
	return !!getpeereid(fd, puid, pgid);
#else
	(void)fd;
	(void)puid;
	(void)pgid;

	return 1;
#endif
}
#endif

/*
 * After a drop, confirm the process really has the credentials we asked for,
 * and cannot simply take root back, eg, through a saved set-user-id of 0.
 */

static int
lws_plat_drop_verify(struct lws_context *context, int have_user, uid_t uid,
		     int have_group, gid_t gid)
{
#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
	int n;
#endif

	if (have_group && (getgid() != gid || getegid() != gid)) {
		lwsl_cx_err(context, "gid %u, egid %u after drop to %u",
			    (unsigned int)getgid(), (unsigned int)getegid(),
			    (unsigned int)gid);

		return 1;
	}

	if (!have_user)
		return 0;

	if (getuid() != uid || geteuid() != uid) {
		lwsl_cx_err(context, "uid %u, euid %u after drop to %u",
			    (unsigned int)getuid(), (unsigned int)geteuid(),
			    (unsigned int)uid);

		return 1;
	}

#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
	/* if he chose to keep the power to change uid, he can get root back */
	for (n = 0; n < context->count_caps; n++)
		if (context->caps[n] == CAP_SETUID)
			return 0;
#endif

	if (!setuid(0)) {
		lwsl_cx_err(context, "still able to become root after drop");

		return 1;
	}

	return 0;
}

/*
 * actually_drop = 0: called while the context is created, to resolve any user
 * and group names to ids, and confirm the user and group we will become
 * exist, before anything listens.
 *
 * actually_drop = 1: become them.  If this returns nonzero, the process may
 * be left with some of its credentials changed and others not: the callers
 * must not let it carry on serving (see lws_finalize_startup()).
 */

int
lws_plat_drop_app_privileges(struct lws_context *context, int actually_drop)
{
	lws_plat_id_lookup_t lu, lg;
	int have_user, have_group, ret = 1, n;
	gid_t gid;

	/* eg, the app called lws_finalize_startup() itself earlier */
	if (actually_drop && context->privs_dropped)
		return 0;

	memset(&lu, 0, sizeof(lu));
	memset(&lg, 0, sizeof(lg));

	/* if he gave us the groupname, align gid to match it */

	if (context->groupname) {
		if (lws_plat_group_to_gid(context->groupname, &gid)) {
			lwsl_cx_err(context, "unknown groupname '%s'",
				    context->groupname);
			return 1;
		}

		lwsl_cx_info(context, "group %s -> gid %u",
			     context->groupname, (unsigned int)gid);
		context->gid = gid;
	}

	/* if he gave us the username, align uid to match it */

	if (context->username) {
		uid_t uid;

		if (lws_plat_user_to_uid(context->username, &uid)) {
			lwsl_cx_err(context, "unknown username '%s'",
				    context->username);
			return 1;
		}

		context->uid = uid;
		lwsl_cx_info(context, "username %s -> uid %u",
			     context->username, (unsigned int)uid);
	}

	/*
	 * "Not given" is 0 (a memset info struct) or -1.  A numeric uid or gid
	 * must exist as much as a named one: find the target user first, we
	 * need his name for initgroups() and his primary group.
	 */

	have_user = context->uid && context->uid != (uid_t)-1;
	if (have_user) {
		n = lws_plat_id_lookup(&lu, LWS_PLAT_ID_USER_BY_UID, NULL,
				       (unsigned int)context->uid);
		if (n) {
			lwsl_cx_err(context, "no user with uid %u (%d)",
				    (unsigned int)context->uid, n);
			goto bail;
		}
	}

	/*
	 * If he named a user but no group, the user's own primary group is the
	 * right answer.  Otherwise we would leave the supposedly unprivileged
	 * process in root's group.
	 */

	gid = context->gid;
	if (have_user && (!gid || gid == (gid_t)-1))
		gid = lu.p->pw_gid;

	have_group = (have_user || gid) && gid != (gid_t)-1;
	if (have_group) {
		n = lws_plat_id_lookup(&lg, LWS_PLAT_ID_GROUP_BY_GID, NULL,
				       (unsigned int)gid);
		if (n) {
			lwsl_cx_err(context, "no group with gid %u (%d)",
				    (unsigned int)gid, n);
			goto bail;
		}
	}

	if (!actually_drop) {
		ret = 0;
		goto bail;
	}

	if (!have_user && !have_group) {
		lwsl_cx_info(context, "not changing user or group");
		ret = 0;
		goto bail;
	}

	/*
	 * Started unprivileged as exactly the user and group we were told to
	 * become, eg, by a service manager: there is nothing to drop
	 */

	if (geteuid() &&
	    (!have_user || (getuid() == context->uid &&
			    geteuid() == context->uid)) &&
	    (!have_group || (getgid() == gid && getegid() == gid))) {
		lwsl_cx_notice(context, "already running as uid %u, gid %u",
			       (unsigned int)geteuid(),
			       (unsigned int)getegid());
		goto verify;
	}

	/*
	 * Every group-side step has to complete while we still have the
	 * privileges to do it, ie, before the setuid().
	 */

	if (have_group) {

		/*
		 * Replace the supplementary group list wholesale, so none of
		 * the privileged process's groups (in particular group 0)
		 * survive the drop.
		 */

		if (have_user) {
			if (initgroups(lu.p->pw_name,
#if defined(__APPLE__)
					(int)
#endif
					gid)) {
				lwsl_cx_err(context, "initgroups: %s failed",
					    strerror(LWS_ERRNO));
				goto bail;
			}
		} else
			if (setgroups(0, NULL)) {
				lwsl_cx_err(context, "setgroups: %s failed",
					    strerror(LWS_ERRNO));
				goto bail;
			}

		if (setgid(gid)) {
			lwsl_cx_err(context, "setgid: %s failed",
				    strerror(LWS_ERRNO));
			goto bail;
		}

		context->gid = gid;
		lwsl_cx_notice(context, "effective group '%s'",
			       lg.g->gr_name);
	} else
		lwsl_cx_info(context, "not changing group");

	/* and only now, the uid... this is what ends our privileges */

	if (have_user) {
#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
		_lws_plat_apply_caps(CAP_PERMITTED, context->caps,
				     context->count_caps);
#endif

		if (setuid(context->uid)) {
			lwsl_cx_err(context, "setuid: %s failed",
				    strerror(LWS_ERRNO));
			goto bail;
		}

		lwsl_cx_notice(context, "effective user '%s'", lu.p->pw_name);

#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
		_lws_plat_apply_caps(CAP_EFFECTIVE, context->caps,
				     context->count_caps);

		for (n = 0; n < context->count_caps; n++)
			lwsl_cx_notice(context, "   RETAINING CAP %d",
				       (int)context->caps[n]);
#endif
	} else
		lwsl_cx_info(context, "not changing user");

verify:
	if (lws_plat_drop_verify(context, have_user, context->uid,
				 have_group, gid))
		goto bail;

	context->privs_dropped = 1;
	ret = 0;

bail:
	lws_plat_id_lookup_destroy(&lu);
	lws_plat_id_lookup_destroy(&lg);

	return ret;
}
