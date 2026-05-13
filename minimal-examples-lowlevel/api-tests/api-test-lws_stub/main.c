/*
 * lws-api-test-lws_stub
 *
 * Written in 2010-2024 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates how to use the lws_stub API to split off a root-privileged
 * process and communicate with it using JSON-RPC over a UDS socket.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#if !defined(WIN32)
#include <unistd.h>
#include <sys/wait.h>
#else
#include <process.h>
#include <io.h>
#define getpid _getpid
#define open _open
#define close _close
#define dup2 _dup2
#endif

static int interrupted;
int is_stub = 0;

/* --- STUB (ROOT) PROCESS --- */

struct pss_stub {
	struct lws *wsi;
	struct lejp_ctx jctx;
	int parser_valid;
	char message[128];
};

static const char * const stub_req_paths[] = { "hello" };

static signed char
stub_req_cb(struct lejp_ctx *ctx, char reason)
{
	struct pss_stub *pss = (struct pss_stub *)ctx->user;

	if (reason == LEJPCB_VAL_STR_END && ctx->path_match - 1 == 0) {
		lws_strncpy(pss->message, ctx->buf, sizeof(pss->message));
		lwsl_notice("Stub received: %s\n", pss->message);
	}

	if (reason == LEJPCB_OBJECT_END) {
		lws_callback_on_writable(pss->wsi);
	}
	return 0;
}

static int
callback_stub_server(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct pss_stub *pss = (struct pss_stub *)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_notice("Stub accepted connection\n");
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!is_stub) {
			/* This is pipe output from the stub process */
			lwsl_notice("STUB-OUTPUT: %.*s", (int)len, (const char *)in);
			break;
		}
		if (!pss->parser_valid) {
			lejp_construct(&pss->jctx, stub_req_cb, pss, stub_req_paths, 1);
			pss->wsi = wsi;
			pss->parser_valid = 1;
		}
		if (lejp_parse(&pss->jctx, (uint8_t *)in, (int)len) < 0) {
			lwsl_err("Stub lejp parse failed\n");
			return -1;
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		{
			char response[128];
			int n = lws_snprintf(response + LWS_PRE, sizeof(response) - LWS_PRE,
					     "{\"reply\":\"Hello from root stub!\"}");
			lws_write(wsi, (unsigned char *)response + LWS_PRE, (size_t)n, LWS_WRITE_RAW);
			return -1; /* Disconnect after sending response */
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (pss->parser_valid)
			lejp_destruct(&pss->jctx);
		break;

	default:
		break;
	}
	return 0;
}

static struct lws_protocols stub_protocols[] = {
	{
		.name = "lws-demo-stub",
		.callback = callback_stub_server,
		.per_session_data_size = sizeof(struct pss_stub),
		.rx_buffer_size = 4096,
	},
	{
		.name = "lws-stub-client",
		.callback = lws_callback_stub_client,
		.per_session_data_size = 0,
		.rx_buffer_size = 4096,
	},
	LWS_PROTOCOL_LIST_TERM
};

static int run_stub(struct lws_context *cx, const char *stub_name)
{
	struct lws_stub_config sc;
	char secret[129];
	char extra[64];

	memset(&sc, 0, sizeof(sc));
	sc.cx = cx;
	sc.stub_name = stub_name;
	sc.uds_path = "/tmp/lws-demo-stub.sock";
	sc.protocols = stub_protocols;

	if (lws_stub_server_init(&sc, secret, extra, sizeof(extra)) < 0) {
		lwsl_err("lws_stub_server_init failed\n");
		return 1;
	}

	lwsl_user("Stub process successfully initialized (secret: %s, extra: %s)\n", secret, extra);

	while (!interrupted)
		lws_service(cx, 0);

	return 0;
}

/* --- PARENT PROCESS --- */

struct parent_state {
	struct lws_context *cx;
	struct lws_stub_manager *mgr;
	char reply[128];
};

static const char * const parent_rx_paths[] = { "reply" };

static signed char
parent_rx_cb(struct lejp_ctx *ctx, char reason)
{
	struct parent_state *ps = (struct parent_state *)ctx->user;

	if (reason == LEJPCB_VAL_STR_END && ctx->path_match - 1 == 0) {
		lws_strncpy(ps->reply, ctx->buf, sizeof(ps->reply));
		lwsl_notice("Parent received reply: %s\n", ps->reply);
	}

	if (reason == LEJPCB_OBJECT_END) {
		lwsl_user("Success: Parent finished communicating with stub.\n");
		interrupted = 1; /* Terminate the event loop safely */
	}

	return 0;
}

static void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;
	const char *p;
	int result = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;



	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	if (lws_cmdline_option(argc, argv, "-h") ||
	    lws_cmdline_option(argc, argv, "--help")) {
		printf("Usage: lws-api-test-lws_stub [-d <log level>]\n"
		       "  -d <log level>    Set LWS log level (default: User+Err+Warn+Notice)\n"
		       "  --help            Show this help message\n\n"
		       "Note: This tool spawns a child process and communicates via UDS.\n"
		       "      Do not pass --lws-stub manually unless you are the spawned child.\n");
		return 0;
	}

	lws_set_log_level(logs, NULL);
	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = stub_protocols;
	info.argc = argc;
	info.argv = argv;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws_create_context failed\n");
		return 1;
	}

	info.vhost_name = "api-test-vhost";
	struct lws_vhost *vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("lws_create_vhost failed\n");
		return 1;
	}

	if ((p = lws_cmdline_option(argc, argv, "--lws-stub="))) {
		/* We are the spawned stub process */
		is_stub = 1;
		char logpath[64];
		int fd;

#if !defined(WIN32)
		lws_snprintf(logpath, sizeof(logpath), "/tmp/stub-log-%d.txt", getpid());
		fd = open(logpath, O_CREAT | O_TRUNC | O_WRONLY, 0644);
		if (fd >= 0) {
			dup2(fd, 2);
			close(fd);
		}
#endif
		lwsl_notice("Stub process starting (PID %d)\n", getpid());
		result = run_stub(cx, p);
	} else {
		/* We are the parent process */
		struct lws_stub_config sc;
		struct parent_state ps;

		memset(&ps, 0, sizeof(ps));
		ps.cx = cx;

		memset(&sc, 0, sizeof(sc));
		sc.cx = cx;
		sc.vh = vh;
		sc.stub_name = "demo-stub";
		sc.uds_path = "/tmp/lws-demo-stub.sock";
		sc.protocols = stub_protocols;
		sc.extra_payload = "initialization_data_for_stub";
		sc.extra_payload_len = strlen((const char *)sc.extra_payload) + 1;

		lwsl_user("Spawning root stub process...\n");
		ps.mgr = lws_stub_spawn(&sc);
		if (!ps.mgr) {
			lwsl_err("Failed to spawn stub process\n");
			result = 1;
			goto done;
		}

		/* Request something from the stub */
		if (lws_stub_request(ps.mgr, "{\"hello\":\"world\"}", parent_rx_paths, 1, parent_rx_cb, NULL, &ps) < 0) {
			lwsl_err("Failed to send request to stub\n");
			result = 1;
			goto done;
		}

		lws_usec_t start = lws_now_usecs();
		while (!interrupted && lws_now_usecs() - start < 5000000) { /* 5s */
			lws_service(cx, 100);
		}

		if (!interrupted) {
			lwsl_err("Timeout waiting for stub!\n");
			result = 1;
		}

done:
		if (ps.mgr)
			lws_stub_destroy(&ps.mgr);
	}

	lws_context_destroy(cx);
	lwsl_user("Exiting with result %d\n", result);
	return lws_cmdline_passfail(argc, argv, result);
}
