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
#define write _write
#define close _close
#define dup2 _dup2
#endif

static int interrupted;
int is_stub = 0;

/* stub names used by the test phases */
#define STUB_NAME	"demo-stub"
#define STUB_NAME_P3	"demo-stub-p3"

/*
 * Where the stub's UDS lives.  The stub child computes exactly the same
 * path for itself from the environment, so parent and child agree where
 * to meet.  All users must go through this one helper so the phases
 * cannot get out of step with the child.
 */
static const char *
stub_uds_path(const char *stub_name)
{
	/* covers MAX_PATH-ish needs on windows and posix alike */
	static char path[300];
#if defined(WIN32)
	const char *tmp = getenv("TMP");

	if (!tmp)
		tmp = getenv("TEMP");
	if (!tmp)
		tmp = ".";

	lws_snprintf(path, sizeof(path), "%s\\lws-%s.sock", tmp, stub_name);
#else
	lws_snprintf(path, sizeof(path), "/tmp/lws-%s.sock", stub_name); // NOSONAR
#endif

	return path;
}

#if !defined(WIN32)
/*
 * Marker file the phase 3 stub child creates from its parent_gone_cb, so
 * the test can prove the autonomous cleanup path really ran in the child
 */
static const char *
stub_gone_marker_path(void)
{
	static char path[300];

	lws_snprintf(path, sizeof(path), "/tmp/lws-%s.gone", STUB_NAME_P3);

	return path;
}
#endif

/*
 * When set, the stub manager is destroyed from PROTOCOL_DESTROY during
 * lws_context_destroy() rather than explicitly by main, the same way the
 * lwsws hls plugin does it.  This covers the teardown ordering where the
 * stub's client wsi is closed and freed by the context destroy machinery
 * before the stub manager itself is destroyed.
 */
static struct lws_stub_manager *g_stub_mgr;

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

	case LWS_CALLBACK_RAW_RX_FILE:
	case LWS_CALLBACK_RAW_RX:
		if (!is_stub) {
			/* This is pipe output from the stub process */
#if !defined(WIN32)
			if (!in) {
				uint8_t buf[4096];
				int n, fd = lws_get_socket_fd(wsi);
				if (fd < 0)
					return -1;
				n = (int)read(fd, buf, sizeof(buf));
				if (n <= 0)
					return -1;
				lwsl_notice("STUB-OUTPUT: %.*s", n, (const char *)buf);
				break;
			}
#endif
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

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		/*
		 * As the protocol named by parent_protocol_name, we must
		 * keep the stub's spawn object informed about its stdwsi
		 * closing, so it can track and clean up after the child
		 */
		if (g_stub_mgr && lws_stub_get_lsp(g_stub_mgr))
			lws_spawn_stdwsi_closed(
				lws_stub_get_lsp(g_stub_mgr), wsi);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (g_stub_mgr)
			lws_stub_destroy(&g_stub_mgr);
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

/*
 * Stub process side: called by lws_stub when it decided the parent has died
 * (or a SIGTERM we would otherwise have died to arrived), just before it
 * unlinks the UDS socket and exits the process autonomously.
 */
static void stub_parent_gone_cb(void *user)
{
	const char *stub_name = (const char *)user;
	char path[300];
	char ok = 'g';
	int fd;

	lwsl_user("Stub '%s': parent gone, running autonomous exit cleanup\n",
		  stub_name);

#if !defined(WIN32)
	if (strcmp(stub_name, STUB_NAME_P3))
		/* only the phase 3 stub leaves a marker for the test */
		return;

	/* leave a marker so the test can prove this ran in the stub child */
	lws_snprintf(path, sizeof(path), "/tmp/lws-%s.gone", stub_name);
	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd >= 0) {
		if (write(fd, &ok, 1) < 0)
			lwsl_err("%s: marker write failed\n", __func__);
		close(fd);
	} else
		lwsl_err("%s: marker open failed\n", __func__);
#else
	(void)path;
	(void)ok;
	(void)fd;
#endif
}

static int run_stub(struct lws_context *cx, const char *stub_name)
{
	struct lws_stub_config sc;
	char secret[129];
	char extra[64];

	memset(&sc, 0, sizeof(sc));
	sc.cx = cx;
	sc.stub_name = stub_name;
	sc.uds_path = stub_uds_path(stub_name);
	sc.protocols = stub_protocols;
	sc.user = (void *)stub_name;
	sc.parent_gone_cb = stub_parent_gone_cb;

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

/*
 * Phase 2: destroy the context while the stub connection is established and
 * the stub manager is only destroyed from PROTOCOL_DESTROY.
 *
 * The vhost used for spawning deliberately does NOT list "lws-stub-client"
 * among its protocols, matching the lwsws hls plugin setup.  The stub must
 * still connect (on its internal client vhost) and the teardown must be
 * clean even though the stub outlives its client wsi until protocol destroy.
 */

static struct lws_protocols parent_protocols[] = {
	{
		.name = "lws-demo-stub",
		.callback = callback_stub_server,
		.per_session_data_size = sizeof(struct pss_stub),
		.rx_buffer_size = 4096,
	},
	LWS_PROTOCOL_LIST_TERM
};

static int established;

static void
phase2_connected_cb(struct lws_stub_manager *mgr)
{
	established = 1;
	lwsl_user("Phase 2: stub client connection established\n");
}

static int
phase2(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_stub_config sc;
	struct lws_context *cx;
	struct lws_vhost *vh;
	lws_usec_t start;

	established = 0;

	lws_context_info_defaults(&info, NULL);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = parent_protocols;
	/* the stub child is a re-exec of this same exe: it needs to be able
	 * to find our executable path via the context */
	info.argc = argc;
	info.argv = argv;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("phase 2: lws_create_context failed\n");
		return 1;
	}

	/*
	 * This vhost lists only lws-demo-stub, NOT lws-stub-client,
	 * deliberately, like the hls plugin's vhost in lwsws
	 */
	info.vhost_name = "phase2-vhost";
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("phase 2: lws_create_vhost failed\n");
		lws_context_destroy(cx);
		return 1;
	}

	memset(&sc, 0, sizeof(sc));
	sc.cx = cx;
	sc.vh = vh;
	sc.stub_name = STUB_NAME;
	sc.uds_path = stub_uds_path(STUB_NAME);
	sc.protocols = stub_protocols;
	sc.parent_protocol_name = "lws-demo-stub";
	/* the stub child always reads the extra payload in this test */
	sc.extra_payload = "phase2";
	sc.extra_payload_len = strlen("phase2") + 1;
	sc.connected_cb = phase2_connected_cb;

	g_stub_mgr = lws_stub_spawn(&sc);
	if (!g_stub_mgr) {
		lwsl_err("phase 2: failed to spawn stub process\n");
		lws_context_destroy(cx);
		return 1;
	}

	start = lws_now_usecs();
	while (!established && lws_now_usecs() - start < 5000000) /* 5s */
		lws_service(cx, 100);

	/* stub is destroyed from PROTOCOL_DESTROY inside here, after its
	 * client wsi was closed and freed */
	lws_context_destroy(cx);

	if (!established) {
		lwsl_err("phase 2: stub connection never established\n");
		return 1;
	}

	return 0;
}

#if !defined(WIN32)

/*
 * Phase 3: prove the stub exits autonomously when its parent dies.
 *
 * We fork an intermediate process that becomes the stub's parent (it spawns
 * the stub and waits for the UDS connection to establish), then SIGKILL the
 * intermediate so it has no chance to clean anything up.  The stub must then
 * notice by itself that its parent is gone, run its parent_gone_cb (observed
 * via the marker file), unlink its UDS socket and exit.
 */

static int p3_established;

static void
phase3_connected_cb(struct lws_stub_manager *mgr)
{
	p3_established = 1;
	lwsl_user("Phase 3: stub client connection established\n");
}

/*
 * This runs in the forked intermediate process that plays the stub's parent.
 * It stays alive with the stub connection established until the real test
 * process kills it with SIGKILL.
 */
static int
phase3_intermediate(int ready_fd, int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_stub_config sc;
	struct lws_context *cx;
	struct lws_vhost *vh;
	lws_usec_t start;
	char ok = '1';

	lws_context_info_defaults(&info, NULL);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = parent_protocols;
	/* the stub child is a re-exec of this same exe */
	info.argc = argc;
	info.argv = argv;

	cx = lws_create_context(&info);
	if (!cx)
		return 1;

	info.vhost_name = "phase3-vhost";
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lws_context_destroy(cx);
		return 1;
	}

	memset(&sc, 0, sizeof(sc));
	sc.cx = cx;
	sc.vh = vh;
	sc.stub_name = STUB_NAME_P3;
	sc.uds_path = stub_uds_path(STUB_NAME_P3);
	sc.protocols = stub_protocols;
	sc.parent_protocol_name = "lws-demo-stub";
	sc.extra_payload = "phase3";
	sc.extra_payload_len = strlen("phase3") + 1;
	sc.connected_cb = phase3_connected_cb;

	g_stub_mgr = lws_stub_spawn(&sc);
	if (!g_stub_mgr) {
		lws_context_destroy(cx);
		return 1;
	}

	start = lws_now_usecs();
	while (!p3_established && lws_now_usecs() - start < 5000000) /* 5s */
		lws_service(cx, 100);

	if (!p3_established) {
		lwsl_err("phase 3: stub connection never established\n");
		return 1;
	}

	/*
	 * Stay alive with the stub connection established for a while, so we
	 * can also prove the stub does NOT clean up while its parent lives
	 */
	start = lws_now_usecs();
	while (lws_now_usecs() - start < 1000000) /* 1s */
		lws_service(cx, 100);

	/* tell the test process we are ready to be killed */
	if (write(ready_fd, &ok, 1) != 1)
		return 1;

	/* keep servicing until the test process SIGKILLs us */
	while (lws_service(cx, 100) >= 0)
		;

	return 0;
}

static int
phase3(int argc, const char **argv)
{
	struct stat st;
	lws_usec_t start;
	int fds[2], pid, n, result = 1;
	char ok;

	/* clean up any leftovers from earlier runs */
	unlink(stub_uds_path(STUB_NAME_P3));
	unlink(stub_gone_marker_path());

	if (pipe(fds)) {
		lwsl_err("phase 3: pipe failed\n");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		lwsl_err("phase 3: fork failed\n");
		close(fds[0]);
		close(fds[1]);
		return 1;
	}

	if (!pid) {
		close(fds[0]);
		_exit(phase3_intermediate(fds[1], argc, argv));
	}

	close(fds[1]);

	/* wait for the intermediate to tell us the stub connection is up */
	n = (int)read(fds[0], &ok, 1);
	close(fds[0]);
	if (n != 1 || ok != '1') {
		lwsl_err("phase 3: intermediate failed to establish the stub connection\n");
		goto bail;
	}

	/*
	 * The stub's parent is still alive: the stub must still be running,
	 * with its UDS socket present and no parent-gone cleanup having run
	 */
	if (!stat(stub_gone_marker_path(), &st)) {
		lwsl_err("phase 3: stub ran parent-gone cleanup while parent alive\n");
		goto bail;
	}
	if (stat(stub_uds_path(STUB_NAME_P3), &st)) {
		lwsl_err("phase 3: stub UDS socket missing while parent alive\n");
		goto bail;
	}

	/* kill the stub's parent with no chance to clean up after itself */
	if (kill(pid, SIGKILL)) {
		lwsl_err("phase 3: kill failed\n");
		goto bail;
	}
	waitpid(pid, NULL, 0);

	/*
	 * The stub should now notice by itself, run its parent_gone_cb (the
	 * marker file appears), unlink its UDS socket and exit
	 */
	start = lws_now_usecs();
	while (lws_now_usecs() - start < 10000000) { /* 10s */
		if (!stat(stub_gone_marker_path(), &st) &&
		    stat(stub_uds_path(STUB_NAME_P3), &st))
			break;
		usleep(100000);
	}

	if (stat(stub_gone_marker_path(), &st)) {
		lwsl_err("phase 3: stub never ran its parent-gone cleanup\n");
		goto bail;
	}

	if (!stat(stub_uds_path(STUB_NAME_P3), &st)) {
		lwsl_err("phase 3: stub left its UDS socket behind\n");
		goto bail;
	}

	lwsl_user("Phase 3: stub detected parent death, cleaned up and exited by itself\n");
	result = 0;

bail:
	/* belt and braces: take down anything still hanging around */
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	unlink(stub_gone_marker_path());

	return result;
}
#endif /* !WIN32 */

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;
	const char *p;
	int result = 0;




	if (lws_cmdline_option(argc, argv, "-h") ||
	    lws_cmdline_option(argc, argv, "--help")) {
		printf("Usage: lws-api-test-lws_stub [-d <log level>]\n"
		       "  -d <log level>    Set LWS log level (default: User+Err+Warn+Notice)\n"
		       "  --help            Show this help message\n\n"
		       "Note: This tool spawns a child process and communicates via UDS.\n"
		       "      Do not pass --lws-stub manually unless you are the spawned child.\n"
		       "      The test runs in phases: request / reply over UDS, teardown at\n"
		       "      context destroy, and the stub noticing its parent died and\n"
		       "      exiting autonomously (POSIX only).\n");
		return 0;
	}

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
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
	sc.stub_name = STUB_NAME;
	sc.uds_path = stub_uds_path(STUB_NAME);
	sc.protocols = stub_protocols;
	sc.parent_protocol_name = "lws-demo-stub";
	sc.extra_payload = "initialization_data_for_stub";
	sc.extra_payload_len = strlen((const char *)sc.extra_payload) + 1;

		lwsl_user("Spawning root stub process...\n");
		ps.mgr = lws_stub_spawn(&sc);
		if (!ps.mgr) {
			lwsl_err("Failed to spawn stub process\n");
			result = 1;
			goto done;
		}
		/* the stub is destroyed from PROTOCOL_DESTROY at context
		 * destroy, like lwsws plugins do it */
		g_stub_mgr = ps.mgr;

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
		} else {
#if defined(WIN32)
			/*
			 * Wait an extra 100ms to ensure the 50ms windows_pipe_poll_hack timer
			 * fires and drains the final child MSVCRT logs before destruction.
			 */
			lws_service(cx, 100);
#endif
		}

done:
		; /* stub destroyed via PROTOCOL_DESTROY during context destroy */
	}

	lws_context_destroy(cx);

	if (!result)
		result = phase2(argc, argv);
#if !defined(WIN32)
	if (!result)
		result = phase3(argc, argv);
#endif

	lwsl_user("Exiting with result %d\n", result);
	return lws_cmdline_passfail(argc, argv, result);
}
