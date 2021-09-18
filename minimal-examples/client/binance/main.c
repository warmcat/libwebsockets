/*
 * lws-minimal-secure-streams-binance
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *                         Kutoga <kutoga@user.github.invalid>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a Secure Streams implementation of a client that connects
 * to binance ws server efficiently.
 *
 * Build lws with -DLWS_WITH_SECURE_STREAMS=1 -DLWS_WITHOUT_EXTENSIONS=0
 *
 * "example-policy.json" contains all the information about endpoints, protocols
 * and connection validation, tagged by streamtype name.
 *
 * The example tries to load it from the cwd, it lives
 * in ./minimal-examples/client/binance dir, so either run it from there, or
 * copy the example-policy.json to your cwd.  It's also possible to put the
 * policy json in the code as a string and pass that at context creation time.
 *
 * When built to use the SSPC proxy, the local policy is not used since the
 * proxy takes care of that.
 */

#include <libwebsockets.h>
#include <signal.h>

static struct lws_context *cx;
static int interrupted;
int test_result = 1;

extern const lws_ss_info_t ssi_binance_t;

static const struct lws_extension extensions[] = {
	{
		"permessage-deflate", lws_extension_callback_pm_deflate,
		"permessage-deflate" "; client_no_context_takeover"
		 "; client_max_window_bits"
	},
	{ NULL, NULL, NULL /* terminator */ }
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;

	lws_context_info_defaults(&info, "example-policy.json");
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	signal(SIGINT, sigint_handler);

	lwsl_user("LWS minimal Secure Streams binance client\n");

	info.extensions = extensions;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (lws_ss_create(cx, 0, &ssi_binance_t, NULL, NULL, NULL, NULL)) {
		lwsl_cx_err(cx, "failed to create secure stream");
		interrupted = 1;
	}

	lws_context_default_loop_run_destroy(cx);

	/* process ret 0 if actual is as expected (0, or--expected-exit 123) */

	return lws_cmdline_passfail(argc, argv, test_result);
}
