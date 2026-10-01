/*
 * lws-api-test-stdin-cmdline
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_system_adopt_stdin(cx, LWS_SAS_FLAG__APPEND_COMMANDLINE) folds what
 * arrives on stdin into the commandline seen by lws_cmdline_option_cx(), so
 * secrets can be passed to the app without appearing in its visible argv.
 *
 * Each case puts some stdin content in a regular file on fd 0, which lws
 * reads to EOF inside lws_system_adopt_stdin(), and then checks what an
 * option resolves to.
 *
 * Content that ends without a trailing newline, as from
 * `printf -- '--x=y' | app`, is ordinary usage, so the last token must come
 * out as a complete C string like the others: the cases cover a last token
 * that is a --switch=value, a bare --switch, the value of a spaced switch,
 * and a non-switch argument.
 */

#include <libwebsockets.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct stdin_case {
	const char		*content;	/* what is on stdin */
	const char		*sw;		/* NULL: first non-switch arg */
	const char		*expect;	/* what sw must resolve to */
} stdin_case_t;

static const stdin_case_t cases[] = {
	{ "--first=one\n--last=final\n",	"--last",	"final" },
	{ "--first=one\n--last=final",		"--last",	"final" },
	{ "--first=one\n--last=final",		"--first",	"one" },
	{ "--a=1 --bare",			"--bare",	"" },
	{ "--a=1\n--spaced value",		"--spaced",	"value" },
	{ "--a=1\nnonswitch",			NULL,		"nonswitch" },
};

/*
 * Replace fd 0 with an unlinked regular file holding content
 */

static int
stdin_from(const char *content)
{
	char path[] = "lws-api-test-stdin-XXXXXX";
	size_t len = strlen(content);
	int fd, ret = 1;
	mode_t um;

	/* nobody else gets to open it in the moment before the unlink */
	um = umask(0077);
	fd = mkstemp(path);
	umask(um);
	if (fd < 0) {
		lwsl_err("%s: unable to create temp file\n", __func__);
		return 1;
	}
	/* the fd keeps the content alive, nothing is left in the fs */
	unlink(path);

	if (write(fd, content, len) != (ssize_t)len ||
	    lseek(fd, 0, SEEK_SET) ||
	    dup2(fd, 0) < 0)
		lwsl_err("%s: unable to prepare stdin\n", __func__);
	else
		ret = 0;

	if (fd)
		close(fd);

	return ret;
}

static int
run_case(int argc, const char **argv, const stdin_case_t *c)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;
	const char *p;
	int ret = 1;

	if (stdin_from(c->content))
		return 1;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* lws_cmdline_option_cx() needs the process commandline to append to */
	info.argc = argc;
	info.argv = argv;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: context creation failed\n", __func__);
		return 1;
	}

	if (lws_system_adopt_stdin(cx, LWS_SAS_FLAG__APPEND_COMMANDLINE)) {
		lwsl_err("%s: failed to adopt stdin\n", __func__);
		goto bail;
	}

	p = lws_cmdline_option_cx(cx, c->sw);
	if (!p || strcmp(p, c->expect)) {
		lwsl_err("%s: %s: expected '%s', got '%s'\n", __func__,
			 c->sw ? c->sw : "(non-switch)", c->expect,
			 p ? p : "(none)");
		goto bail;
	}

	ret = 0;

bail:
	lws_context_destroy(cx);

	return ret;
}

int
main(int argc, const char **argv)
{
	int e = 0;
	size_t n;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: stdin appended to commandline\n");

	for (n = 0; n < LWS_ARRAY_SIZE(cases); n++) {
		if (run_case(argc, argv, &cases[n])) {
			lwsl_err("%s: case %d FAILED\n", __func__, (int)n);
			e++;
		} else
			lwsl_user("%s: case %d: %s -> '%s' OK\n", __func__,
				  (int)n, cases[n].sw ? cases[n].sw :
				  "(non-switch)", cases[n].expect);
	}

	lwsl_user("Completed: %s\n", e ? "FAIL" : "PASS");

	return lws_cmdline_passfail(argc, argv, e);
}
