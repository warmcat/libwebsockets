/*
 * api-test-auth-js — F-050 render-boundary fence for the auth
 * server login widget
 *
 * The login widget JS (plugins/protocol_lws_auth_server/assets/auth.js)
 * composes strings into innerHTML.  The dangerous one is the
 * service_name urlarg, straight from window.location.search: the core
 * URI fence (F-018a) allows VCHAR including <>"', and /api/status
 * answers lacks_grant for any service the logged-in user lacks — so
 * an attacker-crafted /auth?service_name=<markup> link reflected the
 * raw param into innerHTML on the auth origin (F-021 class, F-050).
 *
 * This test reads the actual asset bytes that get served and asserts
 * the fence: the shared escaper is present, every dynamic string at a
 * render boundary goes through lwsAuthEsc(), and no unescaped
 * interpolation of the known-dangerous fields survives.
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
		"function lwsAuthEsc",
		/* the reflected urlarg at the lacks-grant status box (F-050) */
		"lwsAuthEsc(serviceName || 'required service')",
		/* /api/status-sourced fields, defense-in-depth */
		"lwsAuthEsc(data.email || 'Unknown User')",
		"lwsAuthEsc(k)",
		"lwsAuthEsc(lg.ip)",
		"lwsAuthEsc(errData.error || 'Untrusted Redirect URI')",
	};

	/* raw, unescaped interpolations that must not come back */
	static const char * const fence_banned[] = {
		"${serviceName",
		"${data.email",
		"<td>${k}</td>",
		"<td class=\"ip-col\">${lg.ip}</td>",
		"${errData.error",
	};

	fd = lws_open(AUTH_JS_ASSET, LWS_O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: unable to open " AUTH_JS_ASSET "\n", __func__);
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
		lwsl_err("%s: " AUTH_JS_ASSET " too large / truncated\n",
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
		lwsl_user("LWS auth-js fence: FAILED\n");
		return 1;
	}

	lwsl_user("LWS auth-js fence: "
		  "all innerHTML render boundaries escaped\n");
	return 0;
}
