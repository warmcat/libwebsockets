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

/*
 * Opaque handle for one queued request, valid until the request is retired.
 * Zero is never a valid handle, and handles are never reused, so a handle
 * kept after its request was retired is simply dead and safe to pass to
 * lws_stub_request_cancel().
 */
typedef uint64_t lws_stub_req_h;

struct lws_stub_config {
	struct lws_context		*cx;
	struct lws_vhost		*vh;
	const char			*stub_name;		/* e.g. "distribution-client" */
	const char			*uds_path;		/* e.g. "/var/run/lws-cert-dist-stub.sock" */
	const struct lws_protocols	*protocols;		/* Protocol array for the UDS server vhost */
	const void			*extra_payload;		/* Optional extra data to write to child stdin */
	size_t				extra_payload_len;
	void				*user;			/* Opaque user pointer passed to vhost */
	void (*connected_cb)(struct lws_stub_manager *mgr);	/* Called when UDS connects */
	void (*parent_gone_cb)(void *user);			/* Stub process side only: called when the
								 * stub is about to exit autonomously
								 * because its parent died (or SIGTERM was
								 * received and no app handler was
								 * installed), just before the UDS socket
								 * is unlinked and the process exits.  This
								 * is the stub's last chance to clean up
								 * or persist its own state. */
	const char			*parent_protocol_name;	/* Protocol to bind parent pipes to.  If set, this
								 * protocol must call lws_spawn_stdwsi_closed()
								 * with lws_stub_get_lsp(mgr) from its
								 * LWS_CALLBACK_RAW_CLOSE_FILE handler. */
};

struct lws_stub_manager;

/**
 * lws_stub_spawn() - Spawn a root stub process
 *
 * \param config: pointer to the stub configuration
 *
 * Spawns a child process using lws_spawn_piped, appending --lws-stub=<stub_name>.
 * It generates a 128-byte secure random secret and writes it to the child's stdin.
 * The client connection to the stub is made on an internal no-listen vhost that
 * this call creates, so the vhost in config->vh does not need to have registered
 * a "lws-stub-client" protocol.
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
 *
 * On platforms with getppid() and sigaction(), the stub also arranges to
 * detect that the parent process that spawned it has died (it notices it has
 * been re-parented, and, where lws_spawn armed it, accepts the resulting
 * SIGTERM instead of dying abruptly to it).  When that happens, the stub
 * calls config->parent_gone_cb() if set, unlinks its UDS socket (only if the
 * socket file is still its own) and exits the process autonomously.  A stub
 * process has no reason to exist without its parent, so no other shutdown
 * path is taken or possible.
 *
 * Returns 0 on success, < 0 on failure.
 */
LWS_VISIBLE LWS_EXTERN int
lws_stub_server_init(const struct lws_stub_config *config, char *secret_out, void *extra_out, size_t extra_len);

/**
 * lws_stub_request() - Send a JSON-RPC request to the stub
 *
 * \param mgr: The manager returned by lws_stub_spawn
 * \param json: Complete JSON string to send to the stub
 * \param rx_paths: Array of lejp paths to match in the response
 * \param rx_paths_count: Number of paths in the array
 * \param rx_cb: LEJP callback to handle the parsed response JSON, or NULL
 * \param raw_cb: callback given the reply bytes verbatim, or NULL
 * \param user: Opaque user pointer passed to the callbacks
 *
 * Queues an asynchronous JSON request over the UDS connection to the stub.
 * The underlying connection is managed automatically (connect/retry).
 * Returns 0 if queued, < 0 if failed.
 *
 * Same as lws_stub_request_h() below, but without giving you the handle you
 * would need to cancel the request.
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
 * lws_stub_request_h() - Send a JSON-RPC request to the stub, cancellably
 *
 * \param mgr: The manager returned by lws_stub_spawn
 * \param json: Complete JSON string to send to the stub
 * \param rx_paths: Array of lejp paths to match in the response
 * \param rx_paths_count: Number of paths in the array
 * \param rx_cb: LEJP callback to handle the parsed response JSON, or NULL
 * \param raw_cb: callback given the reply bytes verbatim, or NULL
 * \param user: Opaque user pointer passed to the callbacks
 *
 * As lws_stub_request(), but returns a handle for the queued request, or 0 if
 * it could not be queued.
 *
 * Requests are sent, and their replies consumed, strictly in the order they
 * were queued: the channel carries no request ids.
 *
 * A request with neither callback is "fire and forget", and is retired as
 * soon as it has been written.  A request with either callback expects a
 * reply, and is retired when the JSON reply completes (that is the only
 * framing the reply has), or when the reply cannot be parsed, or when the
 * UDS connection closes with the request on the wire, or when the manager is
 * destroyed.
 *
 * Exactly one end-of-request notification is issued, whichever of those it
 * was: LEJPCB_DESTRUCTED to \p rx_cb, and a call of \p raw_cb with \p in NULL
 * and \p len 0.  After it, the request's handle is dead and \p user is no
 * longer held.
 *
 * \p user is held until the request is retired, so if it can go away before
 * then (eg, it is a pss), keep the handle and use lws_stub_request_cancel().
 */
LWS_VISIBLE LWS_EXTERN lws_stub_req_h
lws_stub_request_h(struct lws_stub_manager *mgr,
		   const char *json,
		   const char * const *rx_paths,
		   size_t rx_paths_count,
		   signed char (*rx_cb)(struct lejp_ctx *ctx, char reason),
		   void (*raw_cb)(const char *in, size_t len, void *user),
		   void *user);

/**
 * lws_stub_request_cancel() - Drop a request whose owner is going away
 *
 * \param mgr: The manager returned by lws_stub_spawn
 * \param h: The handle from lws_stub_request_h(), or 0
 *
 * Detaches the request named by \p h from its callbacks and its user pointer,
 * so nothing can reach the owner through it any more.  A request that has not
 * been written yet simply disappears; one that is already on the wire stays
 * at the head of the queue so its reply still gets consumed, but the reply is
 * discarded and the request retired when it completes (or immediately, if the
 * connection closes first).
 *
 * The end-of-request notification described above is issued synchronously
 * from inside this call, while the owner is still alive, and never
 * afterwards.  Cancelling 0, an unknown handle, or a request that was already
 * retired, does nothing.
 */
LWS_VISIBLE LWS_EXTERN void
lws_stub_request_cancel(struct lws_stub_manager *mgr, lws_stub_req_h h);

/**
 * lws_stub_destroy() - Destroy a stub manager
 *
 * \param _mgr: pointer to the manager pointer to destroy
 *
 * Kills the child process and frees all resources.
 */
LWS_VISIBLE LWS_EXTERN void
lws_stub_destroy(struct lws_stub_manager **_mgr);

/**
 * lws_stub_get_secret() - Retrieve the generated secret for a stub manager
 *
 * \param mgr: The manager returned by lws_stub_spawn
 *
 * Returns pointer to the 128-char secret string, or NULL if mgr is invalid.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_stub_get_secret(struct lws_stub_manager *mgr);

/**
 * lws_stub_get_lsp() - Get the spawn object associated with a stub manager
 *
 * \param mgr: The manager returned by lws_stub_spawn
 *
 * Returns the lws_spawn_piped object used for the stub child process, or
 * NULL if mgr is invalid.  If you set parent_protocol_name in the stub
 * config, your protocol handler receives events from the spawn stdwsi; it
 * must call lws_spawn_stdwsi_closed() with this lsp from its
 * LWS_CALLBACK_RAW_CLOSE_FILE handler, so the spawn object can track its
 * stdwsi and clean up correctly.
 */
LWS_VISIBLE LWS_EXTERN struct lws_spawn_piped *
lws_stub_get_lsp(struct lws_stub_manager *mgr);


LWS_VISIBLE LWS_EXTERN int
lws_callback_stub_client(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len);

#endif /* LWS_WITH_STUB */

#endif /* _LWS_STUB_H */
