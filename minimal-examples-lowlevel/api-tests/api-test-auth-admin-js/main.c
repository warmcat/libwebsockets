/*
 * api-test-auth-admin-js — F-049 render-boundary fence for the auth
 * server admin panel
 *
 * The admin panel JS (plugins/protocol_lws_auth_server/assets/admin.js)
 * composes ws-sourced strings (client_id, client display name,
 * redirect_uris, grant service names) into innerHTML and data-*
 * attributes.  Those strings are co-admin-controlled storage: the
 * ws surface is gated by a '*' wildcard grant, but any *-grant
 * co-admin can plant markup that every other admin's panel executes
 * on the next clients_list_reply / list_reply render (F-021 class,
 * stored XSS between co-admins).
 *
 * This test reads the actual asset bytes that get served and asserts
 * the fence: the shared escaper is present, every server-sourced
 * dynamic string at a render boundary goes through lwsAdminEsc(),
 * and no unescaped interpolation of the known-dangerous fields
 * survives.
 *
 * Copyright 2010-2026 Andy Green <andy@warmcat.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <libwebsockets.h>

#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int
main(int argc, const char **argv)
{
	int n, fd, fail = 0, fi;
	static char buf[32768];
	size_t len = 0;
	(void)argc; (void)argv;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);

	/* must exist, and the escaper definition must be in the served bytes */
	static const char * const fence_need[] = {
		"function lwsAdminEsc",
		/* client table: text + attribute contexts */
		"lwsAdminEsc(c.client_id)",
		"lwsAdminEsc(c.name)",
		"lwsAdminEsc(c.redirect_uris)",
		/* users table: grant service names, serialized grants,
		 * username at the render boundary */
		"lwsAdminEsc(k)",
		"lwsAdminEsc(JSON.stringify(u.grants))",
		"lwsAdminEsc(u.user)",
	};

	/* raw, unescaped interpolations that must not come back */
	static const char * const fence_banned[] = {
		"${c.client_id}",
		"${c.name}",
		"${c.redirect_uris}",
		"data-grants='${JSON.stringify",
		"data-user=\"${u.user}\"",
		"<b>${u.user}</b>",
	};

	fd = lws_open(AUTH_ADMIN_JS_ASSET, LWS_O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: unable to open " AUTH_ADMIN_JS_ASSET "\n", __func__);
		return 1;
	}

	while (len < sizeof(buf) - 1) {
		n = (int)read(fd, buf + len, sizeof(buf) - 1 - len);
		if (n < 0) {
			lwsl_err("%s: read failed\n", __func__);
			close(fd);
			return 1;
		}
		if (!n)
			break;
		len += (size_t)n;
	}
	close(fd);
	buf[len] = '\0';

	if (len == sizeof(buf) - 1) {
		lwsl_err("%s: " AUTH_ADMIN_JS_ASSET " too large / truncated\n",
			 __func__);
		return 1;
	}

	for (fi = 0; fi < (int)LWS_ARRAY_SIZE(fence_need); fi++)
		if (!strstr(buf, fence_need[fi])) {
			lwsl_err("%s: fence missing: '%s'\n", __func__,
				 fence_need[fi]);
			fail = 1;
		}

	for (fi = 0; fi < (int)LWS_ARRAY_SIZE(fence_banned); fi++)
		if (strstr(buf, fence_banned[fi])) {
			lwsl_err("%s: fence bypassed: '%s' present\n", __func__,
				 fence_banned[fi]);
			fail = 1;
		}

	if (fail) {
		lwsl_user("LWS auth-admin-js fence: FAILED\n");
		return 1;
	}

	lwsl_user("LWS auth-admin-js fence: "
		  "all innerHTML / data-* render boundaries escaped\n");
	return 0;
}
