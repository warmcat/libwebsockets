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

#ifndef _LWS_STUB_H
#define _LWS_STUB_H

#if defined(LWS_WITH_STUB)

struct lws_stub_manager;

struct lws_stub_config {
	struct lws_context *cx;
	struct lws_vhost *vh;
	const char *stub_name;         /* e.g. "distribution-client" */
	const char *uds_path;          /* e.g. "/var/run/lws-cert-dist-stub.sock" */
	const struct lws_protocols *protocols; /* Protocol array for the UDS server vhost */
	const void *extra_payload;     /* Optional extra data to write to child stdin */
	size_t extra_payload_len;
	void *user;                    /* Opaque user pointer passed to vhost */
	void (*connected_cb)(struct lws_stub_manager *mgr); /* Called when UDS connects */
};

struct lws_stub_manager;

/**
 * lws_stub_spawn() - Spawn a root stub process
 *
 * \param config: pointer to the stub configuration
 *
 * Spawns a child process using lws_spawn_piped, appending --lws-stub=<stub_name>.
 * It generates a 128-byte secure random secret and writes it to the child's stdin.
 * Returns an opaque manager object, or NULL on failure.
 */
LWS_VISIBLE LWS_EXTERN struct lws_stub_manager *
lws_stub_spawn(const struct lws_stub_config *config);

/**
 * lws_stub_server_init() - Initialize the UDS server inside the stub process
 *
 * \param config: pointer to the stub configuration
 * \param secret_out: buffer of at least 129 bytes to store the received secret
 *
 * Called by the child stub process upon startup. It reads the secret from stdin,
 * creates a raw UDS vhost bound to config->uds_path with 0600 permissions,
 * and sets up JSON-RPC dispatching for config->rpc_methods.
 * Returns 0 on success, < 0 on failure.
 */
LWS_VISIBLE LWS_EXTERN int
lws_stub_server_init(const struct lws_stub_config *config, char *secret_out, void *extra_out, size_t extra_len);

/**
 * lws_stub_rpc_request() - Send a JSON-RPC request to the stub
 *
 * \param mgr: The manager returned by lws_stub_spawn
 * \param json: Complete JSON string to send to the stub
 * \param rx_paths: Array of lejp paths to match in the response
 * \param rx_paths_count: Number of paths in the array
 * \param rx_cb: LEJP callback to handle the parsed response JSON
 * \param user: Opaque user pointer passed to the callback
 *
 * Queues an asynchronous JSON request over the UDS connection to the stub.
 * The underlying connection is managed automatically (connect/retry).
 * Returns 0 if queued, < 0 if failed.
 */
LWS_VISIBLE LWS_EXTERN int
lws_stub_request(struct lws_stub_manager *mgr,
		 const char *json,
		 const char * const *rx_paths,
		 size_t rx_paths_count,
		 signed char (*rx_cb)(struct lejp_ctx *ctx, char reason),
		 void (*raw_cb)(const char *in, size_t len, void *user),
		 void *user);

/**
 * lws_stub_destroy() - Destroy a stub manager
 *
 * \param _mgr: pointer to the manager pointer to destroy
 *
 * Kills the child process and frees all resources.
 */
LWS_VISIBLE LWS_EXTERN void
lws_stub_destroy(struct lws_stub_manager **_mgr);


LWS_VISIBLE LWS_EXTERN int
lws_callback_stub_client(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len);

#endif /* LWS_WITH_STUB */

#endif /* _LWS_STUB_H */
