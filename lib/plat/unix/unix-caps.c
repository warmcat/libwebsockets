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

int
lws_plat_user_to_uid(const char *username, uid_t *puid)
{
	struct passwd *p = NULL;

	if (!username || !username[0])
		return 1;

	/* check if numeric string */
	{
		char *endptr = NULL;
		long val = strtol(username, &endptr, 10);
		if (*endptr == '\0' && val >= 0) {
			*puid = (uid_t)val;
			return 0;
		}
	}

#if defined(LWS_HAVE_GETPWNAM_R)
	{
		struct passwd pr;
		char strs[1024];

		if (getpwnam_r(username, &pr, strs, sizeof(strs), &p) || !p) {
#else
	{
		p = getpwnam(username);
		if (!p) {
#endif
			lwsl_err("%s: unknown user '%s'\n", __func__, username);

			return 1;
		}
		*puid = p->pw_uid;
	}

	return 0;
}

int
lws_plat_group_to_gid(const char *groupname, gid_t *pgid)
{
	struct group *g = NULL;

	if (!groupname || !groupname[0])
		return 1;

	/* check if numeric string */
	{
		char *endptr = NULL;
		long val = strtol(groupname, &endptr, 10);
		if (*endptr == '\0' && val >= 0) {
			*pgid = (gid_t)val;
			return 0;
		}
	}

#if defined(LWS_HAVE_GETGRNAM_R)
	{
		struct group gr;
		char strs[1024];

		if (getgrnam_r(groupname, &gr, strs, sizeof(strs), &g) || !g) {
#else
	{
		g = getgrnam(groupname);
		if (!g) {
#endif
			lwsl_err("%s: unknown group '%s'\n", __func__, groupname);

			return 1;
		}
		*pgid = g->gr_gid;
	}

	return 0;
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

int
lws_plat_drop_app_privileges(struct lws_context *context, int actually_drop)
{
	struct passwd *p = NULL;
	struct group *g = NULL;

	/* if he gave us the groupname, align gid to match it */

	if (context->groupname) {
		gid_t gid;
		if (!lws_plat_group_to_gid(context->groupname, &gid)) {
			lwsl_cx_info(context, "group %s -> gid %u",
				  context->groupname, (unsigned int)gid);
			context->gid = gid;
		} else {
			lwsl_cx_err(context, "unknown groupname '%s'",
				 context->groupname);
			return 1;
		}
	}

	/* if he gave us the username, align uid to match it */

	if (context->username) {
		uid_t uid;
		if (!lws_plat_user_to_uid(context->username, &uid)) {
			context->uid = uid;
			lwsl_cx_info(context, "username %s -> uid %u",
				  context->username, (unsigned int)uid);
		} else {
			lwsl_cx_err(context, "unknown username %s",
				 context->username);
			return 1;
		}
	}

	if (!actually_drop)
		return 0;

	/* if he gave us the gid or we have it from the groupname, set it */

	if (context->gid && context->gid != (gid_t)-1l) {
#if defined(LWS_HAVE_GETGRGID_R)
		struct group gr;
		char strs[1024];

		if (getgrgid_r(context->gid, &gr, strs, sizeof(strs), &g) || !g) {
#else
		g = getgrgid(context->gid);
		if (!g) {
#endif
			lwsl_cx_err(context, "cannot find name for gid %d",
					context->gid);

			return 1;
		}

		if (setgid(context->gid)) {
			lwsl_cx_err(context, "setgid: %s failed",
				    strerror(LWS_ERRNO));

			return 1;
		}

		lwsl_cx_notice(context, "effective group '%s'", g->gr_name);
	} else
		lwsl_cx_info(context, "not changing group");


	/* if he gave us the uid or we have it from the username, set it */

	if (context->uid && context->uid != (uid_t)-1l) {
#if defined(LWS_HAVE_GETPWUID_R)
		struct passwd pr;
		char strs[1024];

		if (getpwuid_r(context->uid, &pr, strs, sizeof(strs), &p) || !p) {
#else
		p = getpwuid(context->uid);
		if (!p) {
#endif
			lwsl_cx_err(context, "getpwuid: unable to find uid %d",
				 context->uid);
			return 1;
		}

#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
		_lws_plat_apply_caps(CAP_PERMITTED, context->caps,
				     context->count_caps);
#endif

		if (initgroups(p->pw_name,
#if defined(__APPLE__)
				(int)
#endif
				context->gid))
			return 1;

		if (setuid(context->uid)) {
			lwsl_cx_err(context, "setuid: %s failed",
				    strerror(LWS_ERRNO));

			return 1;
		} else
			lwsl_cx_notice(context, "effective user '%s'",
					p->pw_name);

#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
		_lws_plat_apply_caps(CAP_EFFECTIVE, context->caps,
				     context->count_caps);

		if (context->count_caps) {
			int n;
			for (n = 0; n < context->count_caps; n++)
				lwsl_cx_notice(context, "   RETAINING CAP %d",
					    (int)context->caps[n]);
		}
#endif
	} else
		lwsl_cx_info(context, "not changing user");

	return 0;
}
