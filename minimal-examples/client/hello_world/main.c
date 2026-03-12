/*
 * hello_world example
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Demonstrates the simplest example using the LWS high-level SS apis, doing
 * an h2 GET from warmcat.com.
 *
 * It uses the default SS policy and relies on the tls library to know what
 * CAs are trusted.  See hello_world-policy for a version with its own defined
 * policy which specifies the CA to trust.
 *
 *  - main.c:              (this file) boilerplate to create the lws_context
 *			   and event loop
 *  - hello_world-ss.c:    the secure stream user code
 *
 * Configure lws with -DCMAKE_BUILD_TYPE=DEBUG to build verbose logs, enable at
 * runtime by giving -d 1039 or -d 1151 on this example commandline.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_URL,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_URL]	= { "--url",           "Enable --url feature" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <signal.h>

int test_result = 3; /* b0: clr when peer ACKed request, b1: clr when rx done */
extern const lws_ss_info_t ssi_hello_world_t; /* from hello_world-ss.c */
static struct lws_context *cx; /* so the SIGINT handler below can access it */

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int
main(int argc, const char **argv)
{
	const char *url = "https://warmcat.com/index.html", *p;
	struct lws_context_creation_info info;
	struct lws_ss_handle *h;

	lws_context_info_defaults(&info, NULL /* default policy */);
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_cmdline_option_handle_builtin(argc, argv, &info);
	signal(SIGINT, sigint_handler);

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_URL].sw);
	if (p)
		url = p;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lwsl_cx_user(cx, "LWS hello_world example [-d<verb>]\n");

	if (lws_ss_create(cx, 0, &ssi_hello_world_t, NULL, &h, NULL, NULL)) {
		lwsl_cx_err(cx, "failed to create SS");
		goto bail;
	}

	if (lws_ss_set_metadata(h, "endpoint", url, strlen(url))) {
		lwsl_err("%s: failed to use metadata %s\n", __func__, url);
		goto bail;
	}

	lws_context_default_loop_run_destroy(cx);

	/* process ret 0 if result is as expected (0, or --expected-exit 123) */

	return lws_cmdline_passfail(argc, argv, test_result);

bail:
	lws_context_destroy(cx);

	return 1;
}

