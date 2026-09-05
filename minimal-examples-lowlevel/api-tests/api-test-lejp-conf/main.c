/*
 * lws-api-test-lejp-conf
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * tests for lejp-conf scoped ${define} substitution preprocessing, using the
 * public lwsws config apis
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#if defined(WIN32)
#include <direct.h>
#include <io.h>
#define mkdir(x, y) _mkdir(x)
#endif

enum {
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

static const char dirbase[] = "test-lejp-conf";

static int
write_file(const char *path, const char *content)
{
	int fd = lws_open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	size_t len = strlen(content);

	if (fd < 0)
		return 1;

	if (write(fd, content, (unsigned int)len) != (ssize_t)len) {
		close(fd);
		return 1;
	}
	close(fd);

	return 0;
}

/*
 * Create <dirbase>/<case>/conf containing conf, and optionally
 * <dirbase>/<case>/conf.d/<extra name> containing extra.  Existing content
 * from earlier runs is simply overwritten.
 */
static int
setup_case(const char *name, const char *conf,
	   const char *extra_name, const char *extra)
{
	char p[256];

	lws_snprintf(p, sizeof(p), "%s/%s", dirbase, name);
	if (mkdir(p, 0700) && errno != EEXIST)
		return 1;

	lws_snprintf(p, sizeof(p), "%s/%s/conf", dirbase, name);
	if (write_file(p, conf))
		return 1;

	if (extra_name && extra) {
		lws_snprintf(p, sizeof(p), "%s/%s/conf.d", dirbase, name);
		if (mkdir(p, 0700) && errno != EEXIST)
			return 1;

		lws_snprintf(p, sizeof(p), "%s/%s/conf.d/%s", dirbase, name,
			     extra_name);
		if (write_file(p, extra))
			return 1;
	}

	return 0;
}

static int
run_globals(const char *name, struct lws_context_creation_info *info)
{
	static char arena[4096];
	char *cs = arena;
	char dir[128];
	int len = (int)sizeof(arena);

	memset(arena, 0, sizeof(arena));
	memset(info, 0, sizeof(*info));

	lws_snprintf(dir, sizeof(dir), "%s/%s", dirbase, name);

	return lwsws_get_config_globals(info, dir, &cs, &len);
}

static int
run_globals_defs(struct lws_lejp_conf_defs *defs, const char *name,
		 struct lws_context_creation_info *info)
{
	static char arena[4096];
	char *cs = arena;
	char dir[128];
	int len = (int)sizeof(arena);

	memset(arena, 0, sizeof(arena));
	memset(info, 0, sizeof(*info));
	memset(defs, 0, sizeof(*defs));

	lws_snprintf(dir, sizeof(dir), "%s/%s", dirbase, name);

	return lwsws_get_config_globals_defs(defs, info, dir, &cs, &len);
}

/*
 * Check info->reject_service_keywords is exactly expect_count entries all
 * named "name", with exactly one entry for each string in expected[] (order
 * not defined)
 */
static int
rej_check(const struct lws_context_creation_info *info, int expect_count,
	  const char *const *expected)
{
	const struct lws_protocol_vhost_options *rej = info->reject_service_keywords;
	int count = 0, i, hits;

	while (rej) {
		if (rej->name && strcmp(rej->name, "name")) {
			lwsl_err("%s: unexpected reject name '%s'\n",
				 __func__, rej->name);
			return 1;
		}
		count++;
		rej = rej->next;
	}

	if (count != expect_count) {
		lwsl_err("%s: expected %d reject entries, got %d\n", __func__,
			 expect_count, count);
		return 1;
	}

	for (i = 0; i < expect_count; i++) {
		rej = info->reject_service_keywords;
		hits = 0;
		while (rej) {
			if (rej->value && !strcmp(rej->value, expected[i]))
				hits++;
			rej = rej->next;
		}
		if (hits != 1) {
			lwsl_err("%s: expected exactly one '%s', got %d\n",
				 __func__, expected[i], hits);
			return 1;
		}
	}

	return 0;
}

static int
fail(const char *name, const char *why)
{
	lwsl_err("%s: case '%s': %s\n", __func__, name, why);

	return 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int e = 0, n;
	const char *dbg;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	dbg = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw);
	if (dbg != NULL)
		lws_set_log_level(atoi(dbg), NULL);

	lwsl_user("LWS API selftest: lejp-conf scoped defines\n");

	if (mkdir(dirbase, 0700) && errno != EEXIST)
		return fail("setup", "can't create test dir");

	/*
	 * 1: basic defines, use before and after nested scoping, and
	 * concealment of define pairs from wildcarded paths
	 */

	if (setup_case("basic",
		"{\n"
		  "\"global\": {\n"
		    "\"=PKI_ROOT\": \"/var/dnssec\",\n"
		    "\"username\": \"${PKI_ROOT}/bin\",\n"
		    "\"reject-service-keywords\": [\n"
		      "{ \"=K\": \"first\", \"name\": \"${K}-kw\" },\n"
		      "{ \"name\": \"${PKI_ROOT}-kw\" }\n"
		    "]\n"
		  "}\n"
		"}\n", NULL, NULL))
		return fail("basic", "setup");

	n = run_globals("basic", &info);
	if (n)
		e += fail("basic", "parse failed");
	else {
		const char *const rej[] = { "first-kw", "/var/dnssec-kw" };

		if (!info.username || strcmp(info.username, "/var/dnssec/bin"))
			e += fail("basic", "username substitution");
		else if (rej_check(&info, 2, rej))
			e += fail("basic", "reject keywords");
	}

	/*
	 * 2: substitution across lejp string chunk boundaries, both while
	 * accumulating a define value and while producing the substituted
	 * output, with ${...} itself split across chunks
	 */

	{
		char conf[1024], expect[512];
		size_t o = 0;
		int i;

		o += (size_t)lws_snprintf(conf + o, sizeof(conf) - o,
			"{\n\"global\": {\n"
			"\"=ROOT\": \"/var\",\n"
			"\"=LONG\": \"");

		/* 250 a's, so "${ROOT}" straddles the 254-byte chunk seam */
		for (i = 0; i < 250; i++)
			conf[o++] = 'a';
		o += (size_t)lws_snprintf(conf + o, sizeof(conf) - o, "${ROOT}");
		for (i = 0; i < 100; i++)
			conf[o++] = 'b';

		lws_snprintf(conf + o, sizeof(conf) - o,
			"\",\n"
			"\"username\": \"${LONG}/x${ROOT}/y\"\n"
			"}\n}\n");

		o = 0;
		for (i = 0; i < 250; i++)
			expect[o++] = 'a';
		o += (size_t)lws_snprintf(expect + o, sizeof(expect) - o, "/var");
		for (i = 0; i < 100; i++)
			expect[o++] = 'b';
		lws_snprintf(expect + o, sizeof(expect) - o, "/x/var/y");

		if (setup_case("chunky", conf, NULL, NULL))
			return fail("chunky", "setup");

		n = run_globals("chunky", &info);
		if (n)
			e += fail("chunky", "parse failed");
		else if (!info.username ||
			 strcmp(info.username, expect))
			e += fail("chunky", "chunked substitution result");
	}

	/*
	 * 3: inner scopes shadow enclosing defines, and enclosing defines
	 * are still visible after the inner scope closed
	 */

	if (setup_case("shadow",
		"{\n"
		  "\"global\": {\n"
		    "\"=X\": \"outer\",\n"
		    "\"reject-service-keywords\": [\n"
		      "{ \"=X\": \"inner\", \"name\": \"${X}\" }\n"
		    "],\n"
		    "\"groupname\": \"${X}\"\n"
		  "}\n"
		"}\n", NULL, NULL))
		return fail("shadow", "setup");

	n = run_globals("shadow", &info);
	if (n)
		e += fail("shadow", "parse failed");
	else {
		const char *const rej[] = { "inner" };

		if (!info.groupname || strcmp(info.groupname, "outer"))
			e += fail("shadow", "enclosing define after inner use");
		else if (rej_check(&info, 1, rej))
			e += fail("shadow", "inner shadowing");
	}

	/*
	 * 4: redefining in the same scope takes effect from that point
	 */

	if (setup_case("redef",
		"{\n\"global\": {\n"
		  "\"=X\": \"first\",\n"
		  "\"=X\": \"second\",\n"
		  "\"username\": \"${X}\"\n"
		"}\n}\n", NULL, NULL))
		return fail("redef", "setup");

	n = run_globals("redef", &info);
	if (n)
		e += fail("redef", "parse failed");
	else if (!info.username || strcmp(info.username, "second"))
		e += fail("redef", "same-scope redefinition");

	/*
	 * 5: regression, configs without any defines still work
	 */

	if (setup_case("plain",
		"{\n\"global\": {\n"
		  "\"username\": \"plain\",\n"
		  "\"timeout-secs\": \"19\",\n"
		  "\"reject-service-keywords\": [ { \"name\": \"val\" } ]\n"
		"}\n}\n", NULL, NULL))
		return fail("plain", "setup");

	n = run_globals("plain", &info);
	if (n)
		e += fail("plain", "parse failed");
	else {
		const char *const rej[] = { "val" };

		if (!info.username || strcmp(info.username, "plain"))
			e += fail("plain", "username");
		else if (info.timeout_secs != 19)
			e += fail("plain", "timeout-secs");
		else if (rej_check(&info, 1, rej))
			e += fail("plain", "reject keywords");
	}

	/*
	 * 6: each file parses with a fresh set of defines, conf and conf.d
	 * files can both use their own defines
	 */

	if (setup_case("multifile",
		"{\n\"global\": {\n"
		  "\"=A\": \"1\",\n"
		  "\"username\": \"${A}\"\n"
		"}\n}\n",
		"extra",
		"{\n\"global\": {\n"
		  "\"=B\": \"2\",\n"
		  "\"groupname\": \"${B}${B}\"\n"
		"}\n}\n"))
		return fail("multifile", "setup");

	n = run_globals("multifile", &info);
	if (n)
		e += fail("multifile", "parse failed");
	else if (!info.username || strcmp(info.username, "1") ||
		 !info.groupname || strcmp(info.groupname, "22"))
		e += fail("multifile", "per-file defines");

	/*
	 * 7: with a defs container, globals root defines accumulate across
	 * the walked files and stay visible to later walked files
	 */

	if (setup_case("persist",
		"{\n\"global\": {\n"
		  "\"=A\": \"1\",\n"
		  "\"username\": \"${A}\"\n"
		"}\n}\n",
		"extra",
		"{\n\"global\": {\n"
		  "\"=B\": \"2\",\n"
		  "\"groupname\": \"${A}${B}\"\n"
		"}\n}\n"))
		return fail("persist", "setup");

	{
		struct lws_lejp_conf_defs defs;

		n = run_globals_defs(&defs, "persist", &info);
		if (n)
			e += fail("persist", "parse failed");
		else if (!info.username || strcmp(info.username, "1") ||
			 !info.groupname || strcmp(info.groupname, "12"))
			e += fail("persist", "cross-file globals defines");

		lwsac_free(&defs.ac);
	}

	/*
	 * 8: the globals defs container stays visible (read-only) in the
	 * vhost config files, like lwsws does it.  This needs a real
	 * context and a real vhost with a listen port
	 */

	{
		static char arena[8192];
		struct lws_lejp_conf_defs defs;
		struct lws_context_creation_info i;
		struct lws_context *cx;
		char conf[256], *cs = arena;
		int len = (int)sizeof(arena);

		lws_snprintf(conf, sizeof(conf),
			"{\n\"vhosts\": [{\n"
			  "\"name\": \"${VHROOT}-vh\",\n"
			  "\"port\": \"%u\",\n"
			  "\"interface\": \"127.0.0.1\"\n"
			"}]}\n", LEJP_CONF_VH_PORT);

		if (setup_case("vhinstall",
			"{\n\"global\": {\n"
			  "\"=VHROOT\": \"lejp-conf-test\"\n"
			"}\n}\n",
			"vh", conf))
			return fail("vhinstall", "setup");

		memset(&i, 0, sizeof(i));
		i.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
		i.port = CONTEXT_PORT_NO_LISTEN;

		cx = lws_create_context(&i);
		if (!cx) {
			e += fail("vhinstall", "no context");
			goto done_vh;
		}

		memset(&defs, 0, sizeof(defs));
		if (run_globals_defs(&defs, "vhinstall", &info))
			e += fail("vhinstall", "globals parse failed");
		else if (lwsws_get_config_vhosts_defs(&defs, cx, &i,
						      "test-lejp-conf/vhinstall",
						      &cs, &len))
			e += fail("vhinstall", "vhosts parse failed");
		else {
			/* the substituted name must be the one that exists */
			if (!lws_get_vhost_by_name(cx, "lejp-conf-test-vh"))
				e += fail("vhinstall", "substituted vhost name");
			if (lws_get_vhost_by_name(cx, "${VHROOT}-vh"))
				e += fail("vhinstall", "raw name visible");
		}

		lwsac_free(&defs.ac);
		lws_context_destroy(cx);
done_vh:
		;
	}

	/*
	 * error cases: all of these must fail the parse loudly
	 */

	static const struct {
		const char *name, *conf, *why;
	} errors[] = {
		{ "err-unknown",	"{\"global\":{\"username\":\"${NOPE}\"}}",
						"undefined symbol" },
		{ "err-scope",
			"{\"global\":{\"reject-service-keywords\":"
			"[{ \"=K\": \"x\", \"name\": \"y\" }],"
			"\"username\":\"${K}\"}}",
						"define used out of scope" },
		{ "err-num",		"{\"global\":{\"=N\":5}}",
						"non-string define value" },
		{ "err-bool",		"{\"global\":{\"=N\":true}}",
						"non-string define value" },
		{ "err-object",	"{\"global\":{\"=O\":{\"a\":\"b\"}}}",
						"object define value" },
		{ "err-array",		"{\"global\":{\"=O\":[\"a\"]}}",
						"array define value" },
		{ "err-badname",	"{\"global\":{\"=bad name\":\"x\"}}",
						"invalid define name" },
		{ "err-emptyname",	"{\"global\":{\"=\":\"x\"}}",
						"empty define name" },
	};
	size_t i;

	for (i = 0; i < LWS_ARRAY_SIZE(errors); i++) {
		if (setup_case(errors[i].name, errors[i].conf, NULL, NULL))
			return fail(errors[i].name, "setup");

		if (run_globals(errors[i].name, &info) == 0)
			e += fail(errors[i].name, errors[i].why);
	}

	/*
	 * defines must not leak from conf into conf.d/ files either
	 */

	if (setup_case("err-leak",
		"{\n\"global\": {\n"
		  "\"=A\": \"1\",\n"
		  "\"username\": \"${A}\"\n"
		"}\n}\n",
		"leak",
		"{\n\"global\": {\n"
		  "\"username\": \"${A}\"\n"
		"}\n}\n"))
		return fail("err-leak", "setup");

	if (run_globals("err-leak", &info) == 0)
		e += fail("err-leak", "define leaked across files");

	if (e)
		goto bail;

	lwsl_user("Completed: PASS\n");

	return 0;

bail:
	lwsl_user("Completed: FAIL\n");

	return 1;
}
