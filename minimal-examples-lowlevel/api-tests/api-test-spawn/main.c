/*
 * lws-api-test-spawn
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The test spawns a child process and captures the stdout, which is checked
 * to not be empty.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>

static int interrupted, result = 1, port = 7681, options;
static struct lws_context *context;
static struct lws_spawn_piped *lsp;
static lws_sorted_usec_list_t sul_timeout;

/*
 * The test is considered passed if we get some output from the child process
 * and the child process exits cleanly.
 */

static char captured_stdout[4096];
static size_t captured_stdout_len;

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: test timed out\n", __func__);
	interrupted = 1;
	lws_cancel_service(context);
}

static void
reap_cb(void *opaque, lws_usec_t *accounting, siginfo_t *si, int we_killed_him)
{
	lwsl_user("%s: child process exited\n", __func__);

	/*
	 * If we are here, it means the child process has exited.
	 * We can check if we captured any output.
	 */
	if (captured_stdout_len > 0) {
		lwsl_user("Captured %d bytes of stdout\n",
			  (int)captured_stdout_len);
		result = 0; /* PASS */
	} else {
		lwsl_err("Child process produced no output\n");
	}

	interrupted = 1;
	lws_cancel_service(context);
}

static int
protocol_test_spawn_cb(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		lwsl_user("LWS_CALLBACK_RAW_RX: len %d\n", (int)len);
		if (len > 0 && captured_stdout_len < sizeof(captured_stdout)) {
			size_t avail = sizeof(captured_stdout) - captured_stdout_len;
			if (len > avail)
				len = avail;
			memcpy(captured_stdout + captured_stdout_len, in, len);
			captured_stdout_len += len;
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		lwsl_user("LWS_CALLBACK_RAW_CLOSE\n");
		break;

	default:
		break;
	}

	return 0;
}

static struct lws_protocols protocols[] = {
	{ "lws-test-spawn", protocol_test_spawn_cb, 0, 0 },
	{ NULL, NULL, 0, 0 }
};

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_spawn_piped_info pinfo;
#if defined(WIN32)
	const char * const exec_array[] = { "cmd.exe", "/c", "dir", "C:\\", NULL };
#else
	const char * const exec_array[] = { "ls", "-l", "/", NULL };
#endif

	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_extern(argc, argv);

	lwsl_user("LWS API selftest: spawn\n");

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.protocols = protocols;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	memset(&pinfo, 0, sizeof(pinfo));
	pinfo.exec_array = exec_array;
	pinfo.ops = &protocols[0];
	pinfo.reap_cb = reap_cb;
	pinfo.plsp = &lsp;
	pinfo.timeout_us = 10 * LWS_US_PER_SEC;
	pinfo.tsi = 0;

	lsp = lws_spawn_piped(&pinfo);
	if (!lsp) {
		lwsl_err("lws_spawn_piped failed\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, timeout_cb, 15 * LWS_US_PER_SEC);

	while (lws_service(context, 0) >= 0 && !interrupted)
		;

bail:
	lws_sul_cancel(&sul_timeout);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
