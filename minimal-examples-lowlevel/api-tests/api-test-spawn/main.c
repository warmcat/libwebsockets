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

static int interrupted, result = 1;
static struct lws_context *context;

struct spawn_test {
	lws_sorted_usec_list_t	sul_timeout;
	struct lws_spawn_piped	*lsp;
};

#if defined(WIN32)
static const char * const exec_array[] = { "cmd.exe", "/c", "echo lws-test-spawn-data", NULL };
static const char *expected_stdout = "lws-test-spawn-data\r\n";
#else
static const char * const exec_array[] = { "/bin/sh", "-c", "echo lws-test-spawn-data", NULL };
static const char *expected_stdout = "lws-test-spawn-data\n";
#endif

static char captured_stdout[128];
static size_t captured_stdout_len;

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	struct spawn_test *st = lws_container_of(sul, struct spawn_test, sul_timeout);
	lwsl_err("%s: test timed out\n", __func__);
	/* lsp may be NULL if the spawn failed */
	if (st->lsp)
		lws_spawn_piped_kill_child_process(st->lsp);
	interrupted = 1;
	lws_cancel_service(context);
}

static void
reap_cb(void *opaque, lws_usec_t *accounting, siginfo_t *si, int we_killed_him)
{
	lwsl_user("%s: child process exited\n", __func__);

	if (captured_stdout_len != strlen(expected_stdout) ||
	    strncmp(captured_stdout, expected_stdout, captured_stdout_len)) {
               lwsl_err("Captured stdout mismatch. Got:\n");
               lwsl_hexdump_err(captured_stdout, captured_stdout_len);
               lwsl_err("Expected:\n");
               lwsl_hexdump_err(expected_stdout, strlen(expected_stdout));
	} else {
		lwsl_user("Captured expected stdout\n");
		result = 0; /* PASS */
	}

	interrupted = 1;
	lws_cancel_service(context);
}

static int
protocol_test_spawn_cb(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len)
{
	struct spawn_test *st = lws_get_opaque_user_data(wsi);
	char buf[4096];
	ssize_t ilen;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX_FILE:

#if defined(WIN32)
        {
                DWORD rb;
                if (!ReadFile((HANDLE)lws_get_socket_fd(wsi), buf, sizeof(buf), &rb, NULL)) {
                        lwsl_debug("%s: read on stdwsi failed\n", __func__);
                        return -1;
                }
                ilen = rb;
        }
#else
                ilen = read((int)(intptr_t)lws_get_socket_fd(wsi), buf, sizeof(buf));
                if (ilen < 1) {
                        lwsl_debug("%s: read on stdwsi failed\n", __func__);
                        return -1;
                }
#endif


		if (ilen > 0 && captured_stdout_len < sizeof(captured_stdout) - 1) {
			size_t avail = sizeof(captured_stdout) - 1 - captured_stdout_len;
			if (len > avail)
				len = avail;
			memcpy(captured_stdout + captured_stdout_len, buf, (size_t)ilen);
			captured_stdout_len += (size_t)ilen;
			captured_stdout[captured_stdout_len] = '\0';
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		lws_spawn_stdwsi_closed(st->lsp, wsi);
		break;

	default:
		break;
	}

	return 0;
}

static struct lws_protocols protocols[] = {
	{
		.name = "lws-test-spawn",
		.callback = protocol_test_spawn_cb,
	},
	LWS_PROTOCOL_LIST_TERM
};

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_spawn_piped_info pinfo;
	struct spawn_test st;
        const char *env[] = {
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "LANG=en_US.UTF-8",
                NULL
        };

	memset(&pinfo, 0, sizeof(pinfo));
	memset(&info, 0, sizeof info);
	memset(&st, 0, sizeof st);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: spawn\n");

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	pinfo.env_array		= env;
	pinfo.exec_array        = exec_array;
	pinfo.protocol_name     = protocols[0].name;
	pinfo.reap_cb           = reap_cb;
	pinfo.plsp              = &st.lsp;
	pinfo.timeout_us        = 10 * LWS_US_PER_SEC;
	pinfo.tsi               = 0;
	pinfo.vh		= lws_get_vhost_by_name(context, "default");
	pinfo.opaque		= &st;

	st.lsp = lws_spawn_piped(&pinfo);
	if (!st.lsp) {
		lwsl_err("lws_spawn_piped failed\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &st.sul_timeout, timeout_cb, 15 * LWS_US_PER_SEC);

	while (lws_service(context, 0) >= 0 && !interrupted)
		;

bail:
	lws_sul_cancel(&st.sul_timeout);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
