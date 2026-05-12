/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * lws_stub - generalized API for spawning and communicating with root stubs
 * via UDS and JSON-RPC
 */

#include "private-lib-core.h"

#if defined(LWS_WITH_STUB)

struct lws_stub_manager {
	struct lws_context *cx;
	struct lws_vhost *vh;
	char uds_path[256];
	char secret[129];
	struct lws_spawn_piped *lsp;

	const lws_jrpc_method_t *rpc_methods;
};

struct lws_stub_manager *
lws_stub_spawn(const struct lws_stub_config *config)
{
	struct lws_stub_manager *mgr;
	struct lws_spawn_piped_info spawn_info;
	const char *exec_array[5];
	int n = 0;
	uint8_t rand[64];

	mgr = lws_zalloc(sizeof(*mgr), "stub_mgr");
	if (!mgr)
		return NULL;

	mgr->cx = config->cx;
	mgr->vh = config->vh;
	lws_strncpy(mgr->uds_path, config->uds_path, sizeof(mgr->uds_path));
	mgr->rpc_methods = config->rpc_methods;

	/* Generate a secure 128-char secret */
	lws_get_random(mgr->cx, rand, sizeof(rand));
	lws_hex_from_byte_array(rand, sizeof(rand), mgr->secret, sizeof(mgr->secret));

	memset(&spawn_info, 0, sizeof(spawn_info));
	const char *exe_path = lws_cmdline_option_cx_argv0(mgr->cx);
#if defined(__linux__)
	static char plat_exe_buf[256];
	if (!exe_path || exe_path[0] != '/') {
		int m = (int)readlink("/proc/self/exe", plat_exe_buf, sizeof(plat_exe_buf) - 1);
		if (m > 0) {
			plat_exe_buf[m] = '\0';
			exe_path = plat_exe_buf;
		} else {
			exe_path = "/usr/local/bin/lwsws";
		}
	}
#endif

	exec_array[n++] = exe_path;

	/* Construct the stub argument dynamically */
	char stub_arg[128];
	lws_snprintf(stub_arg, sizeof(stub_arg), "--lws-stub=%s", config->stub_name);
	exec_array[n++] = stub_arg;
	exec_array[n++] = NULL;

	spawn_info.exec_array = exec_array;
	spawn_info.vh = mgr->vh;
	spawn_info.protocol_name = "lws-stub"; /* A dummy protocol to hold the spawn */

	mgr->lsp = lws_spawn_piped(&spawn_info);
	if (mgr->lsp) {
		int stdin_fd = (int)(intptr_t)lws_spawn_get_fd_stdxxx(mgr->lsp, 0);
		if (stdin_fd >= 0) {
			if (write(stdin_fd, mgr->secret, 128) < 0) {
				lwsl_err("%s: Failed writing secret to pipe\n", __func__);
			}
		}
	} else {
		lwsl_err("%s: Failed to spawn child process\n", __func__);
		lws_free(mgr);
		return NULL;
	}

	return mgr;
}

static const struct lws_protocols stub_server_protocols[] = {
	{ "lws-stub-server", NULL, 0, 4096, 0, NULL, 0 },
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

int
lws_stub_server_init(const struct lws_stub_config *config, char *secret_out)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh_uds;

	/* 1. Read secret from stdin */
	if (read(0, secret_out, 128) < 64) {
		lwsl_err("%s: Failed to read secret from stdin\n", __func__);
		return -1;
	}
	secret_out[128] = '\0';

	/* 2. Create UDS server vhost */
	memset(&info, 0, sizeof(info));
	info.options = LWS_SERVER_OPTION_UNIX_SOCK | LWS_SERVER_OPTION_ONLY_RAW;
	info.iface = config->uds_path;
	info.protocols = stub_server_protocols;
	info.vhost_name = config->stub_name;

	unlink(info.iface);
	vh_uds = lws_create_vhost(config->cx, &info);
	if (!vh_uds) {
		lwsl_err("%s: Failed to create UDS vhost\n", __func__);
		return -1;
	}

	/* 3. Secure permissions: Only root (and unprivileged clients dropping privs) */
	chmod(info.iface, 0600);

	/* Signal ready */
	lwsl_notice("STUB-READY (%s)\n", config->stub_name);

	return 0;
}

int
lws_stub_rpc_request(struct lws_stub_manager *mgr,
		     const char *method,
		     const char *json_params,
		     void (*on_response)(struct lws_jrpc_obj *resp, void *user),
		     void *user)
{
	/* TODO: Implement JRPC client connection and state machine */
	return -1;
}

void
lws_stub_destroy(struct lws_stub_manager **_mgr)
{
	struct lws_stub_manager *mgr = *_mgr;
	if (!mgr)
		return;

	if (mgr->lsp)
		lws_spawn_piped_kill_child_process(mgr->lsp);

	lws_free(mgr);
	*_mgr = NULL;
}

#endif /* LWS_WITH_STUB */
