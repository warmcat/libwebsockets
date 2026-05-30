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
#include <string.h>

#if defined(WIN32)
#include <fcntl.h>
#include <io.h>
#endif

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#if defined(LWS_WITH_CLIENT)
struct lws_stub_req {
	struct lws_dll2			list;
	char				*tx_buf;
	size_t				tx_len;
	size_t				tx_pos;
	struct lejp_ctx			jctx;
	signed char			(*rx_cb)(struct lejp_ctx *ctx, char reason);
	void				(*raw_cb)(const char *in, size_t len, void *user);
	void				*user;
};

struct lws_stub_manager {
	struct lws_context		*cx;
	struct lws_vhost		*vh;
	char				uds_path[256];
	char				secret[129];
	struct lws_spawn_piped		*lsp;
	struct lws_stub_config		config;

	const struct lws_protocols	*protocols;

	struct lws			*wsi_client;
	struct lws_dll2_owner		reqs;

	lws_sorted_usec_list_t		sul;
	uint16_t			ctry;
	char				stub_arg[128];
	const char			*exec_array[5];
	char				addr[256];
	char				exe_path[256];
};

static int
lws_stub_client_connect(struct lws_stub_manager *mgr);

struct lws_stub_manager *
lws_stub_spawn(const struct lws_stub_config *config)
{
	struct lws_stub_manager *mgr;
	struct lws_spawn_piped_info spawn_info;
	int n = 0;
	uint8_t rand[64];

	mgr = lws_zalloc(sizeof(*mgr), "stub_mgr");
	if (!mgr)
		return NULL;

	mgr->cx = config->cx;
	mgr->vh = config->vh;
	memcpy(&mgr->config, config, sizeof(mgr->config));
	lws_strncpy(mgr->uds_path, config->uds_path, sizeof(mgr->uds_path));
	mgr->protocols = config->protocols;

	/* Generate a secure 128-char secret */
	lws_get_random(mgr->cx, rand, sizeof(rand));
	lws_hex_from_byte_array(rand, sizeof(rand), mgr->secret, sizeof(mgr->secret));

	memset(&spawn_info, 0, sizeof(spawn_info));
	const char *exe_path = "/usr/local/bin/lwsws";

#if defined(__APPLE__)
	{
		uint32_t size = sizeof(mgr->exe_path);
		if (_NSGetExecutablePath(mgr->exe_path, &size) == 0)
			exe_path = mgr->exe_path;
	}
#elif defined(__linux__)
	{
		int m = (int)readlink("/proc/self/exe", mgr->exe_path, sizeof(mgr->exe_path) - 1);
		if (m > 0) {
			mgr->exe_path[m] = '\0';
			exe_path = mgr->exe_path;
		}
	}
#else
	{
		const char *argv0 = lws_cmdline_option_cx_argv0(mgr->cx);
		if (argv0) {
		if (argv0[0] == '/') {
			lws_strncpy(mgr->exe_path, argv0, sizeof(mgr->exe_path));
			exe_path = mgr->exe_path;
		} else {
#if !defined(WIN32)
			if (realpath(argv0, mgr->exe_path))
				exe_path = mgr->exe_path;
			else
				exe_path = argv0;
#else
			exe_path = argv0;
#endif
		}
		}
	}
#endif

	mgr->exec_array[n++] = exe_path;
	lwsl_notice("%s: Spawning stub with exe: %s\n", __func__, exe_path);
	/* Construct the stub argument dynamically */
	lws_snprintf(mgr->stub_arg, sizeof(mgr->stub_arg), "--lws-stub=%s", config->stub_name);
	mgr->exec_array[n++] = mgr->stub_arg;
	mgr->exec_array[n++] = NULL;

	spawn_info.exec_array = mgr->exec_array;
	spawn_info.vh = mgr->vh;
	if (mgr->protocols)
		spawn_info.protocol_name = mgr->protocols[0].name;

	mgr->lsp = lws_spawn_piped(&spawn_info);
	if (mgr->lsp) {
		lws_filefd_type stdin_fd = lws_spawn_get_fd_stdxxx(mgr->lsp, 0);
#if defined(WIN32)
		if (stdin_fd) {
			DWORD bw;
			if (!WriteFile(stdin_fd, mgr->secret, 128, &bw, NULL)) {
				lwsl_err("%s: Failed writing secret to pipe\n", __func__);
				goto spawn_fail;
			}
			if (config->extra_payload && config->extra_payload_len) {
				if (!WriteFile(stdin_fd, config->extra_payload, (DWORD)config->extra_payload_len, &bw, NULL)) {
					lwsl_err("%s: Failed writing extra payload to pipe\n", __func__);
					goto spawn_fail;
				}
			}
		} else {
			lwsl_err("%s: No stdin pipe available\n", __func__);
			goto spawn_fail;
		}
#else
		if (stdin_fd >= 0) {
			if (write(stdin_fd, mgr->secret, 128) < 0) {
				lwsl_err("%s: Failed writing secret to pipe\n", __func__);
				goto spawn_fail;
			}
			if (config->extra_payload && config->extra_payload_len) {
				if (write(stdin_fd, config->extra_payload, (unsigned int)config->extra_payload_len) < 0) {
					lwsl_err("%s: Failed writing extra payload to pipe\n", __func__);
					goto spawn_fail;
				}
			}
		} else {
			lwsl_err("%s: No stdin pipe available\n", __func__);
			goto spawn_fail;
		}
#endif
	} else {
		lwsl_vhost_err(mgr->vh, "%s: Failed to spawn stub %s\n", __func__, config->stub_name);
		lws_free(mgr);
		return NULL;
	}

	lwsl_vhost_notice(mgr->vh, "%s: Spawned stub %s\n", __func__, config->stub_name);

	if (!mgr->sul.list.owner && !mgr->wsi_client)
		lws_stub_client_connect(mgr);

	return mgr;

spawn_fail:
	lws_spawn_piped_kill_child_process(mgr->lsp);
	lwsl_vhost_err(mgr->vh, "%s: Failed to initialize spawned stub %s\n", __func__, config->stub_name);
	lws_free(mgr);
	return NULL;
}
#endif


int
lws_stub_server_init(const struct lws_stub_config *config, char *secret_out, void *extra_out, size_t extra_len)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh_uds;

	size_t rx = 0;

#if defined(WIN32)
	_setmode(0, _O_BINARY);
#endif

	/* 1. Read secret from stdin */
	while (rx < 128) {
		ssize_t n = read(0, (void *)(secret_out + rx), 128 - (unsigned int)rx);
		if (n <= 0)
			break;
		rx += (size_t)n;
	}

	if (rx < 64) {
		lwsl_err("%s: Failed to read secret from stdin\n", __func__);
		return -1;
	}
	secret_out[128] = '\0';

	/* 1.5. Read extra payload if provided */
	if (extra_out && extra_len > 0) {
		/* We only do a single read here because the payload size is variable
		 * and unknown to the child, and the pipe remains open for future IPC. */
		ssize_t n = read(0, (void *)extra_out, (unsigned int)extra_len);
		if (n < 0) {
			lwsl_err("%s: Failed to read extra payload\n", __func__);
			/* Non-fatal */
		}
	}

	/* 2. Create UDS server vhost */
	memset(&info, 0, sizeof(info));
	info.options = LWS_SERVER_OPTION_UNIX_SOCK | LWS_SERVER_OPTION_ONLY_RAW;
	info.iface = config->uds_path;
	info.protocols = config->protocols;
	info.vhost_name = config->stub_name;
	info.user = config->user;

	unlink(info.iface);
	vh_uds = lws_create_vhost(config->cx, &info);
	if (!vh_uds) {
		lwsl_err("%s: Failed to create UDS vhost\n", __func__);
		return -1;
	}

	/* 3. Secure permissions: Only root (and unprivileged clients dropping privs) */
#if !defined(WIN32)
	chmod(info.iface, 0600);
#endif

	/* Signal ready */
	lwsl_notice("STUB-READY (%s)\n", config->stub_name);

	return 0;
}

#if defined(LWS_WITH_CLIENT)
static const uint32_t backoff_ms[] = { 100, 250, 500, 1000, 5000 };

static const lws_retry_bo_t stub_retry = {
	.retry_ms_table			= backoff_ms,
	.retry_ms_table_count		= LWS_ARRAY_SIZE(backoff_ms),
	.conceal_count			= 1000,
	.secs_since_valid_ping		= 300,
	.secs_since_valid_hangup	= 310,
	.jitter_percent			= 0,
};

static void
stub_retry_cb(lws_sorted_usec_list_t *sul);

static int
lws_stub_client_connect(struct lws_stub_manager *mgr)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= mgr->cx;
	i.vhost			= mgr->vh;

	/* UNIX domain socket addresses need a '+' prefix */
	lws_snprintf(mgr->addr, sizeof(mgr->addr), "+%s", mgr->uds_path);
	i.address		= mgr->addr;

	i.port			= 0;
	i.protocol		= "lws-stub-client";
	i.local_protocol_name	= "lws-stub-client";
	i.host			= NULL;
	i.origin		= NULL;
	i.opaque_user_data	= mgr;
	i.retry_and_idle_policy = &stub_retry;
	i.method		= "RAW"; /* RAW connection */

	lwsl_vhost_notice(mgr->vh, "protocol %s, addr %s\n", i.protocol, i.address);
	mgr->wsi_client = lws_client_connect_via_info(&i);
	if (!mgr->wsi_client) {
		if (mgr->ctry < 10) {
			uint32_t ms = stub_retry.retry_ms_table[
				mgr->ctry < stub_retry.retry_ms_table_count ?
				mgr->ctry : stub_retry.retry_ms_table_count - 1];
			mgr->ctry++;
			if (mgr->ctry > 1)
				lwsl_notice("%s: Synchronous connect failed (errno %d), retrying in %u ms (attempt %d)\n", __func__, LWS_ERRNO, (unsigned int)ms, mgr->ctry);
			lws_sul_schedule(mgr->cx, 0, &mgr->sul, stub_retry_cb, ms * 1000);
		}

		return -1;
	}

	return 0;
}

static void
stub_retry_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_stub_manager *mgr = lws_container_of(sul, struct lws_stub_manager, sul);

	if (!mgr->wsi_client)
		lws_stub_client_connect(mgr);
}

LWS_VISIBLE int
lws_callback_stub_client(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct lws_stub_manager *mgr = (struct lws_stub_manager *)lws_get_opaque_user_data(wsi);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: Client connection failed\n", __func__);
		mgr->wsi_client = NULL;
		lws_retry_sul_schedule(mgr->cx, 0, &mgr->sul, &stub_retry, stub_retry_cb, &mgr->ctry);
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		lwsl_notice("%s: UDS connected to stub\n", __func__);
		mgr->ctry = 0; /* Reset retry counter on success */
		if (mgr->config.connected_cb)
			mgr->config.connected_cb(mgr);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE: {
		struct lws_dll2 *d = lws_dll2_get_head(&mgr->reqs);
		if (!d)
			break;

		struct lws_stub_req *req = lws_container_of(d, struct lws_stub_req, list);
		if (req->tx_pos < req->tx_len) {
			int n = lws_write(wsi, (unsigned char *)req->tx_buf + LWS_PRE + req->tx_pos,
					  req->tx_len - req->tx_pos, LWS_WRITE_RAW);
			if (n < 0)
				return -1;
			req->tx_pos += (size_t)n;
		}

		if (req->tx_pos < req->tx_len) {
			lws_callback_on_writable(wsi);
		} else if (!req->rx_cb && !req->raw_cb) {
			/* No response expected, so we can complete and free the request immediately */
			lws_dll2_remove(&req->list);
			lws_free(req->tx_buf);
			lws_free(req);
			
			/* If there are more requests queued, ask for writable again */
			if (lws_dll2_get_head(&mgr->reqs))
				lws_callback_on_writable(wsi);
		}
		break;
	}

	case LWS_CALLBACK_RAW_RX: {
		struct lws_dll2 *d = lws_dll2_get_head(&mgr->reqs);
		if (!d)
			break; /* Received RX but no active request? */

		struct lws_stub_req *req = lws_container_of(d, struct lws_stub_req, list);
		if (req->raw_cb)
			req->raw_cb((const char *)in, len, req->user);

		if (req->rx_cb) {
			int m = lejp_parse(&req->jctx, (uint8_t *)in, (int)len);
			if (m < 0 && m != LEJP_CONTINUE) {
				lwsl_err("%s: lejp parse failed: %d\n", __func__, m);
				lws_dll2_remove(&req->list);
				lws_free(req->tx_buf);
				lejp_destruct(&req->jctx);
				lws_free(req);
			} else if (req->jctx.pst[req->jctx.pst_sp].callback == NULL) {
				/* If parse complete (or if the callback indicates completion) */
				/* Actually, we can just rely on LEJPCB_OBJECT_END in the callback */
			}
		}
		break;
	}

	case LWS_CALLBACK_CLIENT_CLOSED:
		mgr->wsi_client = NULL;
		break;

	default:
		break;
	}

	return 0;
}

int
lws_stub_request(struct lws_stub_manager *mgr,
		 const char *json,
		 const char * const *rx_paths,
		 size_t rx_paths_count,
		 signed char (*rx_cb)(struct lejp_ctx *ctx, char reason),
		 void (*raw_cb)(const char *in, size_t len, void *user),
		 void *user)
{
	struct lws_stub_req *req = lws_zalloc(sizeof(*req), "stub_req");
	if (!req)
		return -1;

	req->rx_cb	= rx_cb;
	req->raw_cb	= raw_cb;
	req->user	= user;

	if (rx_cb)
		lejp_construct(&req->jctx, rx_cb, user, rx_paths, (uint8_t)rx_paths_count);

	size_t n = strlen(json);
	req->tx_buf = lws_malloc(n + LWS_PRE + 1, "stub_req_tx");
	if (!req->tx_buf) {
		lws_free(req);
		return -1;
	}
	memcpy((unsigned char *)req->tx_buf + LWS_PRE, json, n);
	req->tx_len = n;

	lws_dll2_add_tail(&req->list, &mgr->reqs);

	if (!mgr->wsi_client) {
		if (!mgr->sul.list.owner) {
			if (mgr->ctry >= 10) {
				/* If we hit max retries, reset and try again if new requests come in */
				mgr->ctry = 0;
			}
			lws_stub_client_connect(mgr);
		}
	} else
		lws_callback_on_writable(mgr->wsi_client);

	return 0;
}


void
lws_stub_destroy(struct lws_stub_manager **_mgr)
{
	struct lws_stub_manager *mgr = *_mgr;

	if (!mgr)
		return;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, mgr->reqs.head) {
		struct lws_stub_req *req = lws_container_of(d, struct lws_stub_req, list);
		lws_dll2_remove(d);
		if (req->tx_buf)
			lws_free(req->tx_buf);
		if (req->rx_cb)
			lejp_destruct(&req->jctx);
		lws_free(req);
	} lws_end_foreach_dll_safe(d, d1);

	if (mgr->wsi_client)
		lws_set_opaque_user_data(mgr->wsi_client, NULL);

	if (mgr->lsp)
		lws_spawn_piped_kill_child_process(mgr->lsp);

	unlink(mgr->uds_path);

	lws_free(mgr);
	*_mgr = NULL;
}
#endif
