/*
 * lws-api-test-sysinfo
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Takes a snapshot of the system and prints every item of it the way a
 * daemon logging it at startup would.  Every platform has an lws version and
 * build, a time, and some address on some interface, if only loopback, so
 * those must be there; the rest is what the platform could say.
 */

#include <libwebsockets.h>

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const lws_sysinfo_item_t *it = NULL;
	struct lws_context *cx;
	struct lws_sysinfo *si;
	int seen[LWS_SYSINFO_TYPE_COUNT], n, fail = 0, items = 0;
	char line[256];

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: sysinfo\n");

	memset(seen, 0, sizeof(seen));

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	si = lws_sysinfo_create(cx);
	if (!si) {
		lwsl_err("%s: unable to create snapshot\n", __func__);
		fail = 1;
		goto bail;
	}

	while ((it = lws_sysinfo_next(si, it))) {
		if ((unsigned int)it->type >= LWS_SYSINFO_TYPE_COUNT) {
			lwsl_err("%s: item of unknown type %d\n", __func__,
				 (int)it->type);
			fail = 1;
			continue;
		}

		n = lws_sysinfo_describe(it, line, sizeof(line));
		if (n <= 0 || (size_t)n >= sizeof(line)) {
			lwsl_err("%s: describe said %d\n", __func__, n);
			fail = 1;
			continue;
		}

		lwsl_user("  %s\n", line);
		seen[it->type]++;
		items++;
	}

	lws_sysinfo_destroy(&si);
	if (si) {
		lwsl_err("%s: destroy didn't NULL the snapshot\n", __func__);
		fail = 1;
	}

	if (!seen[LWS_SYSINFO_LWS_VERSION] || !seen[LWS_SYSINFO_LWS_BUILD] ||
	    !seen[LWS_SYSINFO_TIME]) {
		lwsl_err("%s: the lws version, build or time is missing\n",
			 __func__);
		fail = 1;
	}

	if (!seen[LWS_SYSINFO_IFACE_ADDR]) {
		lwsl_err("%s: no interface address at all, not even loopback\n",
			 __func__);
		fail = 1;
	}

	if (!seen[LWS_SYSINFO_HOSTNAME])
		lwsl_warn("%s: no hostname\n", __func__);

bail:
	lws_context_destroy(cx);

	lwsl_user("Completed: %s (%d items)\n", fail ? "FAIL" : "PASS", items);

	return fail;
}
