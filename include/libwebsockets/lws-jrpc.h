/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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
 *
 * This is a JSON-RPC parser and state management implementation that's:
 *
 *  - Lightweight, it uses lws LEJP JSON stream parser for requests, responses,
 *    and user-defined parameter objects
 *
 *  - Stateful... you can give it sequential input buffers randomly fragmented
 *    and it will complete when it has enough
 *
 *  - Asynchronous... response processing can return to the event loop both
 *    while the RX is still coming and after it's all received before forming
 *    the response, eg, because it's querying on a remote connection to get the
 *    response data.  Any number of RPCs can be either in flight or waiting for
 *    response processing to complete before responding.
 *
 *  - Supports "version" extension
 *
 *  - allows binding different method names to different callbacks
 *
 *  - Supports both client and server roles, eg, can parse both requests and
 *    responses
 *
 *  - No support for batch.  Batching is not widely used because it doesn't
 *    add anything for the vast bulk of cases compared to sending n requests.
 *
 * This handles client and server RX and transaction state, creating a callback
 * when parameters can be parsed and all of the request or notification is
 * done.
 *
 * Producing JSON is usually simpler and more compact than expressing it as an
 * object model, ie often a response can be completely formed in a single
 * lws_snprintf().  Response JSON must be buffered on heap until the method
 * callback is called with NULL / 0 buf len indicating that the incoming request
 * has completed parsing.
 *
 */

/* these are opaque */

struct lws_jrpc_obj;
struct lws_jrpc;

typedef enum {
	LJRPC_CBRET_CONTINUE,
	LJRPC_CBRET_WANT_TO_EMIT,
	LJRPC_CBRET_FINISHED,
	LJRPC_CBRET_FAILED
} lws_jrpc_cb_return_t;

/*
 * method name to lejp parsing handler map
 */

typedef struct lws_jrpc_method {
	const char			*method_name;
	const char * const		*paths;
	lejp_callback			cb;
	int				count_paths;
} lws_jrpc_method_t;

/*
 * Boilerplate for forming correct requests
 */

/* Boilerplate to start a request */
#define LWSJRPCBP_REQ_START_S	     "{\"jsonrpc\":\"2.0\",\"method\":\"%s\""
/* Boilerplate to start parameters (params are left freeform for user) */
#define LWSJRPCBP_REQ_VERSION_S	     ",\"version\":\"%s\""
/* Boilerplate to start parameters (params are left freeform for user) */
#define LWSJRPCBP_REQ_PARAMS	     ",\"params\":"
/* Boilerplate to complete the result object */
#define LWSJRPCBP_REQ_NOTIF_END	     "}"
/* Boilerplate to complete the result object */
#define LWSJRPCBP_REQ_ID_END_S	     ",\"id\":%s}"

/*
 * Boilerplate for forming correct responses
 */

/* Boilerplate to start a result */
#define LWSJRPCBP_RESP_RESULT	     "{\"jsonrpc\":\"2.0\",\"result\":"
/* Boilerplate to complete the result object */
#define LWSJRPCBP_RESP_ID_END_S	     ",\"id\":%s}"

/* Boilerplate to form an error */
#define LWSJRPCBP_RESP_ERROR_D	     "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d"
/*   optional */
#define LWSJRPCBP_RESP_ERROR_MSG_S   ",\"message\":\"%s\""
/*   optional */
#define LWSJRPCBP_RESP_ERROR_DATA    ",\"data\":"
/*   required */
#define LWSJRPCBP_RESP_ERROR_END     "}"

/*
 * JSONRPC Well-known Errors
 */

enum {
	LWSJRPCE__NO_ERROR		= 0,

	LWSJRPCWKE__PARSE_ERROR		= -32700, /* invalid JSON */
	LWSJRPCWKE__INVALID_REQUEST	= -32600, /* not valid JSONRPC object */
	LWSJRPCWKE__METHOD_NOT_FOUND	= -32601, /* method not supported */
	LWSJRPCWKE__INVALID_PARAMS	= -32602, /* parameters are invalid */
	LWSJRPCWKE__INTERNAL_ERROR	= -32603, /* internal JSONRPC error */
	LWSJRPCWKE__SERVER_ERROR_FIRST	= -32000, /* implementation-defined...*/
	LWSJRPCWKE__SERVER_ERROR_LAST	= -32099, /* ... server errors range */

	LWSJRPCE__INVALID_MEMBERS	= -31000, /* reponse membs in req, vv */
};

enum {
	LWSJRPC_PARSE_REQUEST,
	LWSJRPC_PARSE_RESPONSE
};

/*
 * APIs for the opaque JRPC request object
 */

/**
 * lws_jrpc_obj_parse() - parse a request or response
 *
 * \param jrpc: the jrpc context this belongs to
 * \param type: LWSJRPC_PARSE_REQUEST or ..._RESPONSE
 * \param opaque: user-defined pointer bound to lws_jrpc, ignored by lws
 * \param buf: chunk of JSON-RPC
 * \param l: remaining length of JSON (may be under or oversize)
 * \param r: NULL to indicate starting new req, already set means continue parse
 *
 * If necessary creates an opaque req object and starts parsing len bytes of
 * buf.  This may be undersize (more parts coming) in which case \p req will be
 * set on entry next time indicating a continuation.
 *
 * \p type and \p opaque are ignored if it it's not the first buffer that
 * creates the req object.
 *
 * Return code is >= 0 if completed, representing the amount of unused data in
 * the input buffer.  -1 indicates more input data needed, <-1 indicates an
 * error from the LWSJRPCWKE_ set above, or LEJP_REJECT_UNKNOWN for OOM
 */

LWS_VISIBLE LWS_EXTERN int
lws_jrpc_obj_parse(struct lws_jrpc *jrpc, int type, void *opaque,
		   const char *buf, size_t l, struct lws_jrpc_obj **r);

/*
 * lws_jrpc_obj_destroy() - detach and destroy a JRPC request or response
 *
 * \param _r: pointer to pointer to JRPC request to detach and free
 *
 * Detaches the req from its JRPC context and frees it and any internal
 * allocations.
 */
LWS_VISIBLE LWS_EXTERN void
lws_jrpc_obj_destroy(struct lws_jrpc_obj **_r);

/*
 * lws_jrpc_obj_get_opaque() - retreive the opaque pointer bound to the req
 *
 * \param r: pointer to pointer to JRPC request
 *
 * Returns the opaque pointer for a req given when it was parsed / created.
 */
LWS_VISIBLE LWS_EXTERN void *
lws_jrpc_obj_get_opaque(const struct lws_jrpc_obj *r);

/*
 * lws_jrpc_obj_id() - retreive the object's id string
 *
 * \param r: pointer to pointer to JRPC object
 *
 * Returns a pointer to a correctly-typed id for use in a response; if a string,
 * then it is already quoted, if an int or null then it's provided without
 * quotes.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_jrpc_obj_id(const struct lws_jrpc_obj *r);


/*
 * APIs for the opaque JRPC context
 */

/**
 * lws_jrpc_create() - Allocate and initialize a JRPC context
 *
 * \param methods: the method callbacks and names we can process
 * \param opaque: user-defined pointer bound to lws_jrpc ignored by lws
 *
 * Allocates an opaque lws_jrpc object and binds it to the given array of
 * method names and callbacks
 */
LWS_VISIBLE LWS_EXTERN struct lws_jrpc *
lws_jrpc_create(const lws_jrpc_method_t *methods, void *opaque);

/*
 * lws_jrpc_destroy() - destroy an allocated JRPC context
 *
 * \param jrpc: pointer to pointer to jrpc to destroy
 *
 * Destroys any ongoing reqs in the JRPC and then destroys the JRPC and sets the
 * given pointer to NULL.
 */
LWS_VISIBLE LWS_EXTERN void
lws_jrpc_destroy(struct lws_jrpc **jrpc);
