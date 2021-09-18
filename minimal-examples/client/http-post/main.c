/*
 * http post example
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Demonstrates http post using the LWS high-level SS apis.
 *
 *  - main.c:              (this file) boilerplate to create the lws_context
 *			   and event loop
 *  - http-post-ss.c:      the secure stream user code
 *  - example-policy.json: the example policy
 */

#include <libwebsockets.h>
#include <signal.h>

/* b0: clr when peer ACKed request, b1: clr when recieved whole response */
int test_result = 3;

extern const lws_ss_info_t ssi_http_post_t; /* from hello_world-ss.c */

static struct lws_context *cx; /* so the SIGINT handler below  can access it */

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

	lwsl_user("LWS SS http-post example [-d<verb>]\n");

	if (!(cx = lws_create_context(&info))) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (lws_ss_create(cx, 0, &ssi_http_post_t, NULL, NULL, NULL, NULL)) {
		lwsl_cx_err(cx, "failed to create get secure stream");
		lws_context_destroy(cx);
		return 1;
	}

	lws_context_default_loop_run_destroy(cx);

	/* process ret 0 if actual is as expected (0, or--expected-exit 123) */

	return lws_cmdline_passfail(argc, argv, test_result);
}
