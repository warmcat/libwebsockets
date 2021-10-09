/*
 * lws-minimal-ss-sink-hello_world
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Simple example registers an SS "sink", it's a streamtype with server-type
 * semantics you can subsequently bind to by creating SS with the same
 * streamtype name.
 *
 * The user code doesn't know if it is being fulfilled by a sink locally, via a
 * SS proxy, or talking to a remote peer, the policy decides it.
 *
 * In the example, we register the sink, then create a source SS.  This also
 * instantiates an accepted sink SS bound to the source.
 *
 * The source sends a message to the accepted sink instance, and that returns
 * a message acknowledging it.
 */

#include <libwebsockets.h>
#include <signal.h>

extern const lws_ss_info_t ssi_myss_sink_t, ssi_myss_src_t;

static struct lws_context *cx;
int test_result = 1, multipart;

static int
smd_cb(void *opaque, lws_smd_class_t c, lws_usec_t ts, void *buf, size_t len)
{
	if (!(c & LWSSMDCL_SYSTEM_STATE))
		return 0;

	if (lws_json_simple_strcmp(buf, len, "\"state\":", "OPERATIONAL"))
		return 0;

	/*
	 * Register our example sink
	 */

	if (lws_ss_create(cx, 0, &ssi_myss_sink_t, NULL, NULL, NULL, NULL)) {
		lwsl_err("%s: unable to register sink\n", __func__);

		return -1;
	}

	/*
	 * Create our example source (which also instantiates an accepted
	 * sink)
	 */

	if (lws_ss_create(cx, 0, &ssi_myss_src_t, NULL, NULL, NULL, NULL)) {
		lwsl_err("%s: unable to register src\n", __func__);

		return -1;
	}

	return 0;
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info *info = malloc(sizeof(*info));

	if (!info)
		return -1;

	lws_context_info_defaults(info, "example-policy.json");
	lws_cmdline_option_handle_builtin(argc, argv, info);
	signal(SIGINT, sigint_handler);

	lwsl_user("LWS Secure Streams Sink hello_world\n");

	info->early_smd_cb		= smd_cb;
	info->early_smd_class_filter	= LWSSMDCL_SYSTEM_STATE;

	cx = lws_create_context(info);
	free(info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_context_default_loop_run_destroy(cx);

	/* process ret 0 if actual is as expected (0, or--expected-exit 123) */

	return lws_cmdline_passfail(argc, argv, test_result);
}
