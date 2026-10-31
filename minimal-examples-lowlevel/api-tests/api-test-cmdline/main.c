/*
 * lws api test cmdline
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * How lws_cmdline_option() / lws_cmdline_options() match a switch, and so
 * how lws_cmdline_option_handle_builtin() applies the builtin switches.
 *
 * A single-letter switch like -d may have its value glued on (-d15).  Any
 * longer switch only matches an argument that is exactly the switch, or the
 * switch followed by =value, never an argument that merely starts with it.
 * So --0rtt-max-size 10 sizes early data without also allowing it (--0rtt),
 * --event selects libevent and not also libev (--ev), and an application's
 * own --h2-prior-knowledge or --h2-port does not force h2 (--h2).
 *
 * Applications move their own switches off the builtins: -h is always help.
 * The builtin -h and --help print the usage and exit(0), which can't be
 * checked in-process: ctest also runs this with -h, and with --help, where
 * getting past the builtins at all is the failure.  Conversely, the builtins
 * exiting while the cases below run (eg, --helpme taken for --help) is
 * turned into a failing exit code.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

static int in_progress;

static void
exit_check(void)
{
	/* something called exit() before we finished: never a pass */
	if (in_progress)
		_Exit(1);
}

static int
expect_str(const char *what, const char *got, const char *want)
{
	if ((!got && !want) || (got && want && !strcmp(got, want)))
		return 0;

	lwsl_err("%s: %s: got %s, expected %s\n", __func__, what,
		 got ? got : "NULL", want ? want : "NULL");

	return 1;
}

static int
expect_hit(const char *what, const char *got, int want)
{
	if (!!got == want)
		return 0;

	lwsl_err("%s: %s: %s, expected %s\n", __func__, what,
		 got ? "matched" : "no match", want ? "a match" : "no match");

	return 1;
}

static int
expect_opt(const char *what, uint64_t options, uint64_t bit, int want)
{
	if (!!(options & bit) == want)
		return 0;

	lwsl_err("%s: %s: option %s, expected %s\n", __func__, what,
		 options & bit ? "set" : "clear", want ? "set" : "clear");

	return 1;
}

/*
 * Apply the builtins to a fresh info for a synthetic commandline.  The
 * caller's log level is kept unless the commandline gives -d.
 */

static void
builtin(struct lws_context_creation_info *info, int logs, int argc,
	const char **argv)
{
	memset(info, 0, sizeof(*info));
	info->default_loglevel = logs;
	lws_cmdline_option_handle_builtin(argc, argv, info);
}

#define AC(_a) ((int)LWS_ARRAY_SIZE(_a))

int
main(int argc, const char **argv)
{
	int e = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	const char *p;

	/* our own commandline: the builtins exit(0) here if given -h / --help */

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	if (lws_cmdline_option(argc, argv, "-h") ||
	    lws_cmdline_option(argc, argv, "--help")) {
		lwsl_err("%s: builtins returned despite -h / --help\n", __func__);
		return 1;
	}

	in_progress = 1;
	if (atexit(exit_check))
		return 1;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);
	lws_set_log_level(logs, NULL);

	lwsl_user("LWS API selftest: cmdline\n");

	/* single-letter switches keep their glued or spaced values */

	{
		const char *a1[] = { "t", "-d15" }, *a2[] = { "t", "-d", "15" },
			   *a3[] = { "t", "-d=15" };

		e += expect_str("-d15", lws_cmdline_option(AC(a1), a1, "-d"),
				"15");
		e += expect_str("-d 15", lws_cmdline_option(AC(a2), a2, "-d"),
				"15");
		e += expect_str("-d=15", lws_cmdline_option(AC(a3), a3, "-d"),
				"15");
	}

	/* a longer switch takes a spaced or = value, nothing glued */

	{
		const char *a1[] = { "t", "--port-r2", "5" },
			   *a2[] = { "t", "--port-r=6" },
			   *a3[] = { "t", "--port-rX" },
			   *a4[] = { "t", "-ip", "1.2.3.4" };

		e += expect_hit("--port-r vs --port-r2",
				lws_cmdline_option(AC(a1), a1, "--port-r"), 0);
		e += expect_str("--port-r2 5",
				lws_cmdline_option(AC(a1), a1, "--port-r2"), "5");
		e += expect_str("--port-r=6",
				lws_cmdline_option(AC(a2), a2, "--port-r"), "6");
		e += expect_hit("--port-rX",
				lws_cmdline_option(AC(a3), a3, "--port-r"), 0);
		e += expect_str("-ip 1.2.3.4",
				lws_cmdline_option(AC(a4), a4, "-ip"), "1.2.3.4");
	}

	/* a val that ends in '=' takes what follows it */

	{
		const char *a1[] = { "t", "--lws-stub=foo" };

		e += expect_str("--lws-stub= glued",
				lws_cmdline_option(AC(a1), a1, "--lws-stub="),
				"foo");
		e += expect_str("--lws-stub =value",
				lws_cmdline_option(AC(a1), a1, "--lws-stub"),
				"foo");
	}

	/* a longer switch before the exact one doesn't hide it */

	{
		const char *a1[] = { "t", "--0rtt-max-size", "10", "--0rtt" };

		e += expect_hit("--0rtt after --0rtt-max-size",
				lws_cmdline_option(AC(a1), a1, "--0rtt"), 1);
	}

	/* walking every instance of a switch skips the longer ones */

	{
		const char *a1[] = { "t", "--form", "a", "--form1", "b",
				     "--form", "c" };

		p = lws_cmdline_options(AC(a1), a1, "--form", NULL);
		e += expect_str("--form 1st", p, "a");
		p = lws_cmdline_options(AC(a1), a1, "--form", p);
		e += expect_str("--form 2nd", p, "c");
		e += expect_hit("--form 3rd",
				lws_cmdline_options(AC(a1), a1, "--form", p), 0);
	}

	/* the builtins */

	{
		const char *a1[] = { "t", "--0rtt-max-size", "10" },
			   *a2[] = { "t", "--0rtt" };

		builtin(&info, logs, AC(a1), a1);
		e += expect_opt("--0rtt-max-size 10: early data", info.options,
				LWS_SERVER_OPTION_ALLOW_EARLY_DATA, 0);
		if (info.quic_0rtt_max_size != 10) {
			lwsl_err("--0rtt-max-size 10: size %u\n",
				 (unsigned int)info.quic_0rtt_max_size);
			e++;
		}

		builtin(&info, logs, AC(a2), a2);
		e += expect_opt("--0rtt: early data", info.options,
				LWS_SERVER_OPTION_ALLOW_EARLY_DATA, 1);
	}

	{
		const char *a1[] = { "t", "--event" }, *a2[] = { "t", "--ev" };

		builtin(&info, logs, AC(a1), a1);
		e += expect_opt("--event: libevent", info.options,
				LWS_SERVER_OPTION_LIBEVENT, 1);
		e += expect_opt("--event: libev", info.options,
				LWS_SERVER_OPTION_LIBEV, 0);

		builtin(&info, logs, AC(a2), a2);
		e += expect_opt("--ev: libevent", info.options,
				LWS_SERVER_OPTION_LIBEVENT, 0);
		e += expect_opt("--ev: libev", info.options,
				LWS_SERVER_OPTION_LIBEV, 1);
	}

	{
		const char *a1[] = { "t", "--h2-prior-knowledge" },
			   *a2[] = { "t", "--h2-port", "7681" },
			   *a3[] = { "t", "--h2" };

		builtin(&info, logs, AC(a1), a1);
		e += expect_opt("--h2-prior-knowledge: force h2", info.options,
				LWS_SERVER_OPTION_CMDLINE_FORCE_H2, 0);

		builtin(&info, logs, AC(a2), a2);
		e += expect_opt("--h2-port: force h2", info.options,
				LWS_SERVER_OPTION_CMDLINE_FORCE_H2, 0);

		builtin(&info, logs, AC(a3), a3);
		e += expect_opt("--h2: force h2", info.options,
				LWS_SERVER_OPTION_CMDLINE_FORCE_H2, 1);
	}

	/*
	 * -H is free for applications: the builtins return (they would exit
	 * on -h, or on --help) and leave it to the application
	 */

	{
		const char *a1[] = { "t", "-H", "x" }, *a2[] = { "t", "--helpme" };

		builtin(&info, logs, AC(a1), a1);
		e += expect_str("-H x", lws_cmdline_option(AC(a1), a1, "-H"),
				"x");
		e += expect_hit("-h in -H x",
				lws_cmdline_option(AC(a1), a1, "-h"), 0);

		builtin(&info, logs, AC(a2), a2);
		e += expect_hit("--help in --helpme",
				lws_cmdline_option(AC(a2), a2, "--help"), 0);
	}

	in_progress = 0;
	lws_set_log_level(logs, NULL);
	lwsl_user("Completed: %s\n", e ? "FAIL" : "PASS");

	return !!e;
}
