/*
 * hello_world-policy example
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Demonstrates the simplest example using the LWS high-level SS apis, doing
 * an h1 GET from warmcat.com.
 *
 * It specifies its own policy and restricts the tls library to validating the
 * certificate through a single trusted CA cert defined in the policy.
 *
 *  - main.c:              (this file) boilerplate to create the lws_context
 *			   and event loop
 *  - hello_world-ss.c:    the secure stream user code
 *  - example-policy.json: the example policy
 *
 * Configure lws with -DCMAKE_BUILD_TYPE=DEBUG to build verbose logs, enable at
 * runtime by giving -d 1039 or -d 1151 on this example commandline.
 */

#include <libwebsockets.h>
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
	struct lws_context_creation_info info;

	lws_context_info_defaults(&info, "example-policy.json");
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	signal(SIGINT, sigint_handler);

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lwsl_cx_user(cx, "LWS hello_world example [-d<verb>]\n");

	if (lws_ss_create(cx, 0, &ssi_hello_world_t, NULL, NULL, NULL, NULL)) {
		lwsl_cx_err(cx, "failed to create SS");
		lws_context_destroy(cx);
		return 1;
	}

	lws_context_default_loop_run_destroy(cx);

	/* process ret 0 if result is as expected (0, or --expected-exit 123) */

	return lws_cmdline_passfail(argc, argv, test_result);
}
