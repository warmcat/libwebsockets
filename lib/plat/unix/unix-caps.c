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
_lws_plat_apply_caps(int mode, const cap_value_t *cv, int count)
{
	cap_t caps;

	if (!count)
		return;

	caps = cap_get_proc();

	cap_set_flag(caps, mode, count, cv, CAP_SET);
	cap_set_proc(caps);
	prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
	cap_free(caps);
}
#endif

int
lws_plat_user_colon_group_to_ids(const char *u_colon_g, uid_t *puid, gid_t *pgid)
{
	char *colon = strchr(u_colon_g, ':'), u[33];
	struct passwd *p;
	struct group *g;
	int ulen;

	if (!colon)
		return 1;

	ulen = lws_ptr_diff(colon, u_colon_g);
	if (ulen < 2 || ulen > (int)sizeof(u) - 1)
		return 1;

	memcpy(u, u_colon_g, ulen);
	u[ulen] = '\0';

	colon++;

	g = getgrnam(colon);
	if (!g) {
		lwsl_err("%s: unknown group '%s'\n", __func__, colon);

		return 1;
	}
	*pgid = g->gr_gid;

	p = getpwnam(u);
	if (!p) {
		lwsl_err("%s: unknown group '%s'\n", __func__, u);

		return 1;
	}
	*puid = p->pw_uid;

	return 0;
}

int
lws_plat_drop_app_privileges(struct lws_context *context, int actually_drop)
{
	struct passwd *p;
	struct group *g;

	/* if he gave us the groupname, align gid to match it */

	if (context->groupname) {
		g = getgrnam(context->groupname);

		if (g) {
			lwsl_info("%s: group %s -> gid %u\n", __func__,
				  context->groupname, g->gr_gid);
			context->gid = g->gr_gid;
		} else {
			lwsl_err("%s: unknown groupname '%s'\n", __func__,
				 context->groupname);

			return 1;
		}
	}

	/* if he gave us the username, align uid to match it */

	if (context->username) {
		p = getpwnam(context->username);

		if (p) {
			context->uid = p->pw_uid;

			lwsl_info("%s: username %s -> uid %u\n", __func__,
				  context->username, (unsigned int)p->pw_uid);
		} else {
			lwsl_err("%s: unknown username %s\n", __func__,
				 context->username);

			return 1;
		}
	}

	if (!actually_drop)
		return 0;

	/* if he gave us the gid or we have it from the groupname, set it */

	if (context->gid && context->gid != -1) {
		g = getgrgid(context->gid);

		if (!g) {
			lwsl_err("%s: cannot find name for gid %d\n",
				  __func__, context->gid);

			return 1;
		}

		if (setgid(context->gid)) {
			lwsl_err("%s: setgid: %s failed\n", __func__,
				 strerror(LWS_ERRNO));

			return 1;
		}

		lwsl_notice("%s: effective group '%s'\n", __func__,
			    g->gr_name);
	} else
		lwsl_info("%s: not changing group\n", __func__);


	/* if he gave us the uid or we have it from the username, set it */

	if (context->uid && context->uid != -1) {
		p = getpwuid(context->uid);

		if (!p) {
			lwsl_err("%s: getpwuid: unable to find uid %d\n",
				 __func__, context->uid);
			return 1;
		}

#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
		_lws_plat_apply_caps(CAP_PERMITTED, context->caps,
				     context->count_caps);
#endif

		if (initgroups(p->pw_name, context->gid))
			return 1;

		if (setuid(context->uid)) {
			lwsl_err("%s: setuid: %s failed\n", __func__,
				  strerror(LWS_ERRNO));

			return 1;
		} else
			lwsl_notice("%s: effective user '%s'\n",
				    __func__, p->pw_name);

#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
		_lws_plat_apply_caps(CAP_EFFECTIVE, context->caps,
				     context->count_caps);

		if (context->count_caps) {
			int n;
			for (n = 0; n < context->count_caps; n++)
				lwsl_notice("   RETAINING CAP %d\n",
					    (int)context->caps[n]);
		}
#endif
	} else
		lwsl_info("%s: not changing user\n", __func__);

	return 0;
}
