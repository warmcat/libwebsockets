/*
 * lws-minimal-secure-streams-server
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Simplest possible SS https server
 */

#include <libwebsockets.h>
#include <signal.h>

extern const lws_ss_info_t ssi_myss_srv_t;

static struct lws_context *cx;
int test_result = 0, multipart;

static int
smd_cb(void *opaque, lws_smd_class_t c, lws_usec_t ts, void *buf, size_t len)
{
	if (!(c & LWSSMDCL_SYSTEM_STATE) ||
	    lws_json_simple_strcmp(buf, len, "\"state\":", "OPERATIONAL") ||
	    !lws_ss_create(cx, 0, &ssi_myss_srv_t, NULL, NULL, NULL, NULL))
		return 0;

	lwsl_err("%s: failed to create secure stream\n", __func__);
	lws_default_loop_exit(cx);

	return -1;
}

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

	lwsl_user("LWS Secure Streams Server\n");

	info.early_smd_cb		= smd_cb;
	info.early_smd_class_filter	= LWSSMDCL_SYSTEM_STATE;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_context_default_loop_run_destroy(cx);

	/* process ret 0 if actual is as expected (0, or--expected-exit 123) */

	return lws_cmdline_passfail(argc, argv, test_result);
}
